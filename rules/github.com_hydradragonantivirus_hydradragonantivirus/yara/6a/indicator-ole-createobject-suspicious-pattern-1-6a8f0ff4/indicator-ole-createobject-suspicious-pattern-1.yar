rule INDICATOR_OLE_CreateObject_Suspicious_Pattern_1 {
    meta:
        author = "ditekSHen"
        description = "Detects OLE with specific waves of pattern"
    strings:
        $action1 = "document_open" ascii nocase
        $s1 = "CreateTextFile" ascii
        $s2 = "CreateObject" ascii
                $pattern = /(\[\w{3,4}\]\w{3,4}){50,100}/ ascii
    condition:
        uint16(0) == 0xcfd0 and 1 of ($action*) and 2 of ($s*) and $pattern
}