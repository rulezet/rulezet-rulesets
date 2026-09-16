rule PEiD_00474_Ding_Boy_s_PE_lock_Phantasm_v1_5b3_ {
  meta:
    description = "[Ding Boy's PE-lock Phantasm v1.5b3]"
    ep_only     = "true"

  strings:
    $a = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

  condition:
    $a
}