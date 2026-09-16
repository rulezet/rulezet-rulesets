rule TTP_XOR_MULT_DOSStub_e648 {
  strings:
    $key_e648 = { b2 20 [2] c6 38 [2] 81 3a [2] c6 2b [2] 88 27 [2] 84 2d [2] 93 26 [2] 88 68 [2] b5 }

  condition:
    any of them
}