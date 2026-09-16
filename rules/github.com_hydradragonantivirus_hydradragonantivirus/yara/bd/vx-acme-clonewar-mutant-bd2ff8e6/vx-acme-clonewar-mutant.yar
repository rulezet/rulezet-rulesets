import "pe"
rule Vx__ACME__Clonewar_Mutant_ {
  strings:
    $a0 = { FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE }

  condition:
    $a0 at pe.entry_point
}