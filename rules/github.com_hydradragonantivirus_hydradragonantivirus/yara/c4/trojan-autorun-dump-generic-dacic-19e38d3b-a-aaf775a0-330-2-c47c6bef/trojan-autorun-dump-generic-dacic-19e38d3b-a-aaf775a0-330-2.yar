rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_330_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_330_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce18744d826b64930e79c39dd6efba61985db840216f5f02c7723b31ee677158"

  strings:
    $s1 = "DOWN?'o" fullword ascii
    $s2 = "~*VERB){" fullword ascii
    $s3 = "gROS(1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}