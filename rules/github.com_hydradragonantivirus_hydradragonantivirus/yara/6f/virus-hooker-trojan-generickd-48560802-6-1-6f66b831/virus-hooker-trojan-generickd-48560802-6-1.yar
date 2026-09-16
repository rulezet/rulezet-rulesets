rule Virus_Hooker_Trojan_GenericKD_48560802_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "131a42c29d3359bbace76b83d8cb864993ca0a849087b8dff8c2511eeaec36e3"

  strings:
    $s1  = "set cdaudio door closed" fullword wide
    $s2  = "spreading" fullword wide
    $s3  = "schtasks /create /sc minute /mo 1 /tn StUpdate /tr " fullword wide
    $s4  = "Shutdown -l" fullword wide
    $s5  = "Shutdown -r" fullword wide
    $s6  = "Shutdown -s" fullword wide
    $s7  = "error < Not Found >" fullword wide
    $s8  = "t detect AV" fullword wide
    $s9  = "Adobe Update" fullword wide
    $s10 = "!~ Hacker ~!" fullword wide
    $s11 = "[shift]" fullword wide
    $s12 = "[pause]" fullword wide
    $s13 = "[home]" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}