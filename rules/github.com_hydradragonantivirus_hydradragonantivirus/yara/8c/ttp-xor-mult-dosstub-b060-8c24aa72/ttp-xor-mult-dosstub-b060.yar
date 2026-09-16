rule TTP_XOR_MULT_DOSStub_b060 {
  strings:
    $key_b060 = { e4 08 [2] 90 10 [2] d7 12 [2] 90 03 [2] de 0f [2] d2 05 [2] c5 0e [2] de 40 [2] e3 }

  condition:
    any of them
}