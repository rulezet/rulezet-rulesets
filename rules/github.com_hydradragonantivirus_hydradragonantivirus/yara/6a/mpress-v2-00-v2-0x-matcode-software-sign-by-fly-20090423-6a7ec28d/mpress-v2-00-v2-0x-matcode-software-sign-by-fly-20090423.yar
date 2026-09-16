import "pe"
rule MPRESS_V2_00_V2_0X____MATCODE_Software_____Sign_By_fly___20090423 {
  strings:
    $a0 = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6 }

  condition:
    $a0 at pe.entry_point
}