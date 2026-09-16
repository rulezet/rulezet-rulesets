import "pe"
rule Upack_v0_24___v0_28_Alpha____Dwing {
  strings:
    $a0 = { BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD }

  condition:
    $a0 at pe.entry_point
}