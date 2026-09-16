rule TTP_XOR_MULT_DOSStub_fb86 {
  strings:
    $key_fb86 = { af ee [2] db f6 [2] 9c f4 [2] db e5 [2] 95 e9 [2] 99 e3 [2] 8e e8 [2] 95 a6 [2] a8 }

  condition:
    any of them
}