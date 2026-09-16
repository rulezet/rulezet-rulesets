rule PEiD_00570_Exe_Shield_v2_7_ {
  meta:
    description = "[Exe Shield v2.7]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }

  condition:
    $a
}