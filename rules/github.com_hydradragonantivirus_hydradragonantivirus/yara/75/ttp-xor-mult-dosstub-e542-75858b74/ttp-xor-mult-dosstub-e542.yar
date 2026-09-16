rule TTP_XOR_MULT_DOSStub_e542 {
  strings:
    $key_e542 = { b1 2a [2] c5 32 [2] 82 30 [2] c5 21 [2] 8b 2d [2] 87 27 [2] 90 2c [2] 8b 62 [2] b6 }

  condition:
    any of them
}