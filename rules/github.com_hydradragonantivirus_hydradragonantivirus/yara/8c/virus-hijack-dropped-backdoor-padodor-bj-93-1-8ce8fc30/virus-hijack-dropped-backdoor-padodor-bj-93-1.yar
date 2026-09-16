rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_93_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_93_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0172ce50f78b05482d3526b42efa3de52f4bff58d594e7d1797fad2a9d640386"

  strings:
    $s1 = "mdd4g<:hill<oDBpqttDwLJxy||L" fullword ascii
    $s2 = "riFt 7VS|" fullword ascii
    $s3 = "ly saved ac2" fullword ascii
    $s4 = "~= NULL&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}