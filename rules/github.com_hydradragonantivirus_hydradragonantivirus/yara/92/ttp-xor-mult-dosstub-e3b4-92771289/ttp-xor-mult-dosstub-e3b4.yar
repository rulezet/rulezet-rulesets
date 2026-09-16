rule TTP_XOR_MULT_DOSStub_e3b4 {
  strings:
    $key_e3b4 = { b7 dc [2] c3 c4 [2] 84 c6 [2] c3 d7 [2] 8d db [2] 81 d1 [2] 96 da [2] 8d 94 [2] b0 }

  condition:
    any of them
}