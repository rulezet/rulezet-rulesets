import "pe"
rule __PseudoSigner_0_1_rule__DxPack_1_0______Anorganix {
  strings:
    $a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9 }

  condition:
    $a0 at pe.entry_point
}