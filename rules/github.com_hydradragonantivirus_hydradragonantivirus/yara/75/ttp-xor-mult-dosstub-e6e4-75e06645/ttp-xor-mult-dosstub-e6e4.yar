rule TTP_XOR_MULT_DOSStub_e6e4 {
  strings:
    $key_e6e4 = { b2 8c [2] c6 94 [2] 81 96 [2] c6 87 [2] 88 8b [2] 84 81 [2] 93 8a [2] 88 c4 [2] b5 }

  condition:
    any of them
}