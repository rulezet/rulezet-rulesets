rule TTP_XOR_MULT_DOSStub_fbd7 {
  strings:
    $key_fbd7 = { af bf [2] db a7 [2] 9c a5 [2] db b4 [2] 95 b8 [2] 99 b2 [2] 8e b9 [2] 95 f7 [2] a8 }

  condition:
    any of them
}