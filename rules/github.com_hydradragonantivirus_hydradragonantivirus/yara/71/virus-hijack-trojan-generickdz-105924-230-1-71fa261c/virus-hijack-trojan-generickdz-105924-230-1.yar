rule Virus_Hijack_Trojan_GenericKDZ_105924_230_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_230_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a6034d3805555af7a4a1589175c948cd034973311d27d51e5db0054346e975"

  strings:
    $s1 = "# created by tools/tclZIC.tcl - do not edit" fullword ascii
    $s2 = "Determining Windows version" fullword wide
    $s3 = "Trying to load SPP based on Windows version" fullword wide
    $s4 = "       transport: tcp | npipe | ssl | spipe | 1394 | com" fullword wide
    $s5 = "Spp loading result" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}