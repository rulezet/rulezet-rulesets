import "pe"
rule Upack_v0_33___v0_34_Beta____Dwing {
  strings:
    $a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }

  condition:
    $a0 at pe.entry_point
}