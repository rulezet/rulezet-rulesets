rule Virus_Hijack_Trojan_GenericKDZ_98113_99 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_99.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "337d98ae0baba0645ffb081f334efed7fe837cfdbc19b39f3871fec9d6b99cb4"

  strings:
    $s1 = "features of the software will stop running.E1C" fullword ascii
    $s2 = "bsingle server or multiple servers, regardless of whether or not the individual is actively using the programs at any given time" ascii
    $s3 = "bsingle server or multiple servers, regardless of whether or not the individual is actively using the programs at any given time" ascii
    $s4 = "yagreements or representations, written or oral, " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}