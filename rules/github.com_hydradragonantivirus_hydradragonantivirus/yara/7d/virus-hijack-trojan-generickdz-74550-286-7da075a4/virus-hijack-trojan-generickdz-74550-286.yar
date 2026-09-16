rule Virus_Hijack_Trojan_GenericKDZ_74550_286 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_286.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fc5467eeabd06cb4c559293233039e7930c149299d6d94191742aeafed9ce61"

  strings:
    $s1 = "mv*w&fEL:`IJhFKL,%dK%gOLd%ZR-dY[d%IQ:wO]<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}