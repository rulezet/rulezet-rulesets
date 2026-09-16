rule PEiD_00043_Ady_s_Glue_v0_10_ {
  meta:
    description = "[Ady`s Glue v0.10]"
    ep_only     = "true"

  strings:
    $a = { 2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F }

  condition:
    $a
}