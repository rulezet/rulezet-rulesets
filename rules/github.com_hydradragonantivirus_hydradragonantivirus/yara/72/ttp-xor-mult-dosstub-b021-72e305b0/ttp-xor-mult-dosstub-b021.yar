rule TTP_XOR_MULT_DOSStub_b021 {
  strings:
    $key_b021 = { e4 49 [2] 90 51 [2] d7 53 [2] 90 42 [2] de 4e [2] d2 44 [2] c5 4f [2] de 01 [2] e3 }

  condition:
    any of them
}