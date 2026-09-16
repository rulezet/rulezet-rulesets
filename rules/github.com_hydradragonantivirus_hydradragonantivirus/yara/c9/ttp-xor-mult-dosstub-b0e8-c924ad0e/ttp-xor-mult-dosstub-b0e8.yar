rule TTP_XOR_MULT_DOSStub_b0e8 {
  strings:
    $key_b0e8 = { e4 80 [2] 90 98 [2] d7 9a [2] 90 8b [2] de 87 [2] d2 8d [2] c5 86 [2] de c8 [2] e3 }

  condition:
    any of them
}