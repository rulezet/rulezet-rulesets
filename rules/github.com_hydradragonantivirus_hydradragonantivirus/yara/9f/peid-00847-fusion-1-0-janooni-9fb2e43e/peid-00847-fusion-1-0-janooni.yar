rule PEiD_00847_Fusion_1_0____jaNooNi_ {
  meta:
    description = "[Fusion 1.0 -> jaNooNi]"
    ep_only     = "true"

  strings:
    $a = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00 }

  condition:
    $a
}