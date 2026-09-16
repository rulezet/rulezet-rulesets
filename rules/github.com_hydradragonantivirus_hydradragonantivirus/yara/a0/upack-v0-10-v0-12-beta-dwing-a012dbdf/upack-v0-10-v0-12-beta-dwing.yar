import "pe"
rule Upack_v0_10___v0_12_Beta____Dwing {
  strings:
    $a0 = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }

  condition:
    $a0 at pe.entry_point
}