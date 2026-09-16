rule TTP_XOR_MULT_DOSStub_b065 {
  strings:
    $key_b065 = { e4 0d [2] 90 15 [2] d7 17 [2] 90 06 [2] de 0a [2] d2 00 [2] c5 0b [2] de 45 [2] e3 }

  condition:
    any of them
}