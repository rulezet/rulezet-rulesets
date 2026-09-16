import "pe"
rule Ding_Boy_s_PE_lock_Phantasm_v0_8 {
  strings:
    $a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

  condition:
    $a0 at pe.entry_point
}