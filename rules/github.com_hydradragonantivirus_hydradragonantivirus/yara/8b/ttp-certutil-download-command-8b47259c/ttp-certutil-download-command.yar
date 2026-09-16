rule TTP_Certutil_Download_command {
    meta:
        description = "Matches strings commonly found in certutil.exe download commands."
        last_modified = "2024-02-21"
        author = "@petermstewart"
        DaysofYara = "52/100"
        ref = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/#download"

    strings:
        $a = "certutil" nocase ascii wide
        $b = "-urlcache" nocase ascii wide
        $c = "-split" nocase ascii wide
        $d = "http" nocase ascii wide

    condition:
        all of them
}