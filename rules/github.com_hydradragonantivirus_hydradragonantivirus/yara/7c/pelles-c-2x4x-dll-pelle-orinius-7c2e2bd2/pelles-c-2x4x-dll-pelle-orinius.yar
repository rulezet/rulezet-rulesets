import "pe"
rule _Pelles_C_2x4x_DLL__Pelle_Orinius_ {
  meta:
    description = "Pelles C 2.x-4.x DLL -> Pelle Orinius"

  strings:
    $0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

  condition:
    $0 at pe.entry_point
}