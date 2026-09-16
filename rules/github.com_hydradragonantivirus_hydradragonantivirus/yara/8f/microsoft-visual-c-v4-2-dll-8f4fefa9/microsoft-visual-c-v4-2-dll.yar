import "pe"
rule Microsoft_Visual_C___v4_2_DLL {
  strings:
    $a0 = { 53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75 }

  condition:
    $a0 at pe.entry_point
}