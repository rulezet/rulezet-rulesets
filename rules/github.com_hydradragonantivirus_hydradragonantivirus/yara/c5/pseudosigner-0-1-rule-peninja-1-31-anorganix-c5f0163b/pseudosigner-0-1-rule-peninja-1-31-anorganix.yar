import "pe"
rule __PseudoSigner_0_1_rule__PENinja_1_31______Anorganix {
  strings:
    $a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }

  condition:
    $a0 at pe.entry_point
}