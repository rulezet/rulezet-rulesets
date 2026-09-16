rule TTP_XOR_MULT_DOSStub_b034 {
  strings:
    $key_b034 = { e4 5c [2] 90 44 [2] d7 46 [2] 90 57 [2] de 5b [2] d2 51 [2] c5 5a [2] de 14 [2] e3 }

  condition:
    any of them
}