import "pe"
rule _Trojan_Autorun_Trojan_Generic_7761207_Trojan_Autorun_Trojan_Gen_98 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.Generic.7761207.vir, Trojan.Autorun_Trojan.Generic.7761207_1.vir, Trojan.Autorun_Trojan.Generic.7761207_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1398f6bf07b9f01da6b840cab8bfb89837b9d231164ec7bf18be33c99eacf8ca"
    hash2       = "e3392456a027283da418f829ec1235380794b178542af5ac9fd907be19a6e1a0"
    hash3       = "9c47e91190e9d7303a2519adacc251f5b4b487b9a3400d61c7b5785fd52f9b16"
    hash4       = "972524af3cff33106c0f9b9805eacd6a36ed5a8123bc40934cf11f760faf44b3"

  strings:
    $s1  = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET4.0C; .NET4.0E)" fullword ascii
    $s2  = "!!!!!!!!!!Read Or Write HD Error Code====0x%x" fullword ascii
    $s3  = "Invalid partition tableMissing operating system" fullword ascii
    $s4  = "Kernel Detective" fullword ascii
    $s5  = "HTTP/1.1 302 Redirect" fullword ascii
    $s6  = "<html><frameset border=0 frameSpacing=0 rows=\"*,0\" frameBorder=NO><frame name=\"main\" marginWidth=0 marginHeight=0 noresize s" ascii
    $s7  = "HTTP/1.1 307 Redirect" fullword ascii
    $s8  = "IoCallDriver 0x%x fail 0x%x" fullword ascii
    $s9  = "Master Boot Record Wrote by MBR By DiskGenius" fullword ascii
    $s10 = "[domain]" fullword ascii
    $s11 = "START PAGE" fullword wide
    $s12 = "Windows Player" fullword wide
    $s13 = "[adad]" fullword ascii
    $s14 = "[anti]" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "52a948b5de7cc38ae8e6110ce48389ff" and (8 of them)
    ) or (all of them)
}