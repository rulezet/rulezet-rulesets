rule VirusShareBackDoorRndseed17_1 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorRndseed17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cb00bf6600a743afa44b4e00f254d6fbc4cacaf918ba1d862b1bccea83cd971"

  strings:
    $s1 = "Copyright Node.js contributors.MIT lisence." fullword wide
    $s2 = "2D Adventure Game" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}