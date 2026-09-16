rule TTP_XOR_MULT_DOSStub_e644 {
  strings:
    $key_e644 = { b2 2c [2] c6 34 [2] 81 36 [2] c6 27 [2] 88 2b [2] 84 21 [2] 93 2a [2] 88 64 [2] b5 }

  condition:
    any of them
}