import "pe"
rule Microsoft_Visual_C___DLL {
  strings:
    $a0 = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }
    $a1 = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14 }
    $a2 = { 53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}