rule TTP_XOR_MULT_DOSStub_fb81 {
  strings:
    $key_fb81 = { af e9 [2] db f1 [2] 9c f3 [2] db e2 [2] 95 ee [2] 99 e4 [2] 8e ef [2] 95 a1 [2] a8 }

  condition:
    any of them
}