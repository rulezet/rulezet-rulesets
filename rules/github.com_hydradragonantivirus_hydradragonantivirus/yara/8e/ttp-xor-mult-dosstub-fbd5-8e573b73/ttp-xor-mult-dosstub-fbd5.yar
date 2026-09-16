rule TTP_XOR_MULT_DOSStub_fbd5 {
  strings:
    $key_fbd5 = { af bd [2] db a5 [2] 9c a7 [2] db b6 [2] 95 ba [2] 99 b0 [2] 8e bb [2] 95 f5 [2] a8 }

  condition:
    any of them
}