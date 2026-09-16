rule Trojan_Danger_Trojan_Agent_CQST_4 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.CQST_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeedebf7532accb51d3599d010865000bcdb3dd377205d25ff8dbf05df15e242"

  strings:
    $s1 = "D(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "D(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s3 = "and software vendors, so that they can use the information to i`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}