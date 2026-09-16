rule TTP_XOR_MULT_DOSStub_e643 {
  strings:
    $key_e643 = { b2 2b [2] c6 33 [2] 81 31 [2] c6 20 [2] 88 2c [2] 84 26 [2] 93 2d [2] 88 63 [2] b5 }

  condition:
    any of them
}