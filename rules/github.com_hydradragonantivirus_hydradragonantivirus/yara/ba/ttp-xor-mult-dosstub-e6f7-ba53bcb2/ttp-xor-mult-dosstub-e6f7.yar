rule TTP_XOR_MULT_DOSStub_e6f7 {
  strings:
    $key_e6f7 = { b2 9f [2] c6 87 [2] 81 85 [2] c6 94 [2] 88 98 [2] 84 92 [2] 93 99 [2] 88 d7 [2] b5 }

  condition:
    any of them
}