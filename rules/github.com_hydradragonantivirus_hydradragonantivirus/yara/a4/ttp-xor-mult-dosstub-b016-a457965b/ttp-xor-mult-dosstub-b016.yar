rule TTP_XOR_MULT_DOSStub_b016 {
  strings:
    $key_b016 = { e4 7e [2] 90 66 [2] d7 64 [2] 90 75 [2] de 79 [2] d2 73 [2] c5 78 [2] de 36 [2] e3 }

  condition:
    any of them
}