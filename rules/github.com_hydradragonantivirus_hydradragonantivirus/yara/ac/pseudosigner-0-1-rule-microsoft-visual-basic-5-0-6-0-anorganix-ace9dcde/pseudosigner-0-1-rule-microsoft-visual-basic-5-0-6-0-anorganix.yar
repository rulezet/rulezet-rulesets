import "pe"
rule __PseudoSigner_0_1_rule__Microsoft_Visual_Basic_5_0___6_0______Anorganix {
  strings:
    $a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

  condition:
    $a0 at pe.entry_point
}