rule TTP_XOR_MULT_DOSStub_b744 {
  strings:
    $key_b744 = { e3 2c [2] 97 34 [2] d0 36 [2] 97 27 [2] d9 2b [2] d5 21 [2] c2 2a [2] d9 64 [2] e4 }

  condition:
    any of them
}