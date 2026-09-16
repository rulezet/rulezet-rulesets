rule TTP_XOR_MULT_DOSStub_e242 {
  strings:
    $key_e242 = { b6 2a [2] c2 32 [2] 85 30 [2] c2 21 [2] 8c 2d [2] 80 27 [2] 97 2c [2] 8c 62 [2] b1 }

  condition:
    any of them
}