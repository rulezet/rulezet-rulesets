rule TTP_XOR_MULT_DOSStub_b0e9 {
  strings:
    $key_b0e9 = { e4 81 [2] 90 99 [2] d7 9b [2] 90 8a [2] de 86 [2] d2 8c [2] c5 87 [2] de c9 [2] e3 }

  condition:
    any of them
}