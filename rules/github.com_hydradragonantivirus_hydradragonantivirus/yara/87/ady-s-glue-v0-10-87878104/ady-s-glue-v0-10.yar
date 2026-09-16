import "pe"
rule Ady_s_Glue_v0_10 {
  strings:
    $a0 = { 2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F }

  condition:
    $a0 at pe.entry_point
}