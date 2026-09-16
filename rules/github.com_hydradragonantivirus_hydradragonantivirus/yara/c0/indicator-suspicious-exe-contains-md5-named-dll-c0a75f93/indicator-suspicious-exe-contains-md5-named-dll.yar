rule INDICATOR_SUSPICIOUS_EXE_Contains_MD5_Named_DLL {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = /[a-f0-9]{32}\.dll/ ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}