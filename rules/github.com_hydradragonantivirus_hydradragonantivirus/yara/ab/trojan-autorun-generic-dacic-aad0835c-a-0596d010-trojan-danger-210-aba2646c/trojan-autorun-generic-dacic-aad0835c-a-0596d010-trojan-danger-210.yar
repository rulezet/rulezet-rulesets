import "pe"
rule _Trojan_Autorun_Generic_Dacic_AAD0835C_A_0596D010_Trojan_Danger__210 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Generic.Dacic.AAD0835C.A.0596D010.vir, Trojan.Danger_Trojan.GenericKD.72853156_293_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_384_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d85b0ad0e682ea993a1912f678f798568001180d9a742e99007be15fb5eafc"
    hash2       = "fe5ed94732cba2a5401dc7683d1e032592e4274a1d3db98eb45e94ac6a4c9427"
    hash3       = "bbd927a84b13eb50adc593bbc01bbefcc610170193a62f0eeb463cd195398850"

  strings:
    $s1 = "turn false'8drag)" fullword ascii
    $s2 = "name : " fullword ascii
    $s3 = "<BODY  onc`" fullword ascii
    $s4 = "^xt&Copy W" fullword ascii
    $s5 = "?{open" fullword ascii
    $s6 = "LeftBtom" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "39a774befcd1acb895cf30a7ff631743" and (all of them)
    ) or (all of them)
}