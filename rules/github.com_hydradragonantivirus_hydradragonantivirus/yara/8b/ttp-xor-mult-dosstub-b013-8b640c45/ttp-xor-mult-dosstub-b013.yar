rule TTP_XOR_MULT_DOSStub_b013 {
  strings:
    $key_b013 = { e4 7b [2] 90 63 [2] d7 61 [2] 90 70 [2] de 7c [2] d2 76 [2] c5 7d [2] de 33 [2] e3 }

  condition:
    any of them
}