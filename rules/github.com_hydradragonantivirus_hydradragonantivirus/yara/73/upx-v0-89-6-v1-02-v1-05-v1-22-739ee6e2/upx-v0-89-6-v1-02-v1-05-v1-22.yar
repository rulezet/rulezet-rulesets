import "pe"
rule UPX_v0_89_6___v1_02___v1_05___v1_22 {
  strings:
    $a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }

  condition:
    $a0 at pe.entry_point
}