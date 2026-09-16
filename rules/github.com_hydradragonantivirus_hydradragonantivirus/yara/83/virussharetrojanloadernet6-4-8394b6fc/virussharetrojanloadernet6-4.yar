rule VirusShareTrojanLoaderNET6_4 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanLoaderNET6_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b89a0d32282aec22683f39a1fbcb3bc67fb1ff2ace8373ea9c4d29ea46d7298"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "Window Security Startup.exe" fullword wide
    $s3 = "Window Security Startup" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}