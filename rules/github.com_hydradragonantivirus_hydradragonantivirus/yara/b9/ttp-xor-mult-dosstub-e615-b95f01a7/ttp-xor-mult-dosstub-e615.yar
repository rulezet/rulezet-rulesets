rule TTP_XOR_MULT_DOSStub_e615 {
  strings:
    $key_e615 = { b2 7d [2] c6 65 [2] 81 67 [2] c6 76 [2] 88 7a [2] 84 70 [2] 93 7b [2] 88 35 [2] b5 }

  condition:
    any of them
}