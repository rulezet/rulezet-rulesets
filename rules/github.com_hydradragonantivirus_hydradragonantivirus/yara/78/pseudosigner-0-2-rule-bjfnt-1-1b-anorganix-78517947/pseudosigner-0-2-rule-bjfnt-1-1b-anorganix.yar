import "pe"
rule __PseudoSigner_0_2_rule___BJFNT_1_1b______Anorganix {
  strings:
    $a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }

  condition:
    $a0 at pe.entry_point
}