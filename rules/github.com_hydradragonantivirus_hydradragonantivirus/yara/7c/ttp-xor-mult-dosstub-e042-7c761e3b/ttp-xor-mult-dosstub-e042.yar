rule TTP_XOR_MULT_DOSStub_e042 {
  strings:
    $key_e042 = { b4 2a [2] c0 32 [2] 87 30 [2] c0 21 [2] 8e 2d [2] 82 27 [2] 95 2c [2] 8e 62 [2] b3 }

  condition:
    any of them
}