rule W32ChirB_LastResort
{
    meta:
        Description = ""

    strings:
        $a = "runouce.exe" ascii wide
        $b = /.{1,20}@btamail.net.cn/ fullword ascii nocase
        $c = "ChineseHacker-2" ascii wide

    condition:
        all of them
}