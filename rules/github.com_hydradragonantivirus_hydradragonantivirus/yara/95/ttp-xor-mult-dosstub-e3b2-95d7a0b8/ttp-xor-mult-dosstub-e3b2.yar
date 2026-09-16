rule TTP_XOR_MULT_DOSStub_e3b2 {
  strings:
    $key_e3b2 = { b7 da [2] c3 c2 [2] 84 c0 [2] c3 d1 [2] 8d dd [2] 81 d7 [2] 96 dc [2] 8d 92 [2] b0 }

  condition:
    any of them
}