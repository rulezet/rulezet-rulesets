rule TTP_XOR_MULT_DOSStub_e645 {
  strings:
    $key_e645 = { b2 2d [2] c6 35 [2] 81 37 [2] c6 26 [2] 88 2a [2] 84 20 [2] 93 2b [2] 88 65 [2] b5 }

  condition:
    any of them
}