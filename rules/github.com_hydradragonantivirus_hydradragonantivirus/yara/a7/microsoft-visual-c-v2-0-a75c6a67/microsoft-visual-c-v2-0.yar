import "pe"
rule Microsoft_Visual_C_v2_0 {
  strings:
    $a0 = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75 }

  condition:
    $a0 at pe.entry_point
}