rule TTP_PowerShell_Download_command {
    meta:
        description = "Matches strings commonly found in PowerShell download cradles."
        last_modified = "2024-02-20"
        author = "@petermstewart"
        DaysofYara = "51/100"
        ref = "https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters"

    strings:
        $a = "powershell" nocase ascii wide
        $b = "IEX" nocase ascii wide
        $c = "New-Object" nocase ascii wide
        $d = "Net.Webclient" nocase ascii wide
        $e = ".downloadstring(" nocase ascii wide

    condition:
        4 of them
}