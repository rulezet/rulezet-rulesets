rule TTP_XOR_MULT_DOSStub_e6f5 {
  strings:
    $key_e6f5 = { b2 9d [2] c6 85 [2] 81 87 [2] c6 96 [2] 88 9a [2] 84 90 [2] 93 9b [2] 88 d5 [2] b5 }

  condition:
    any of them
}