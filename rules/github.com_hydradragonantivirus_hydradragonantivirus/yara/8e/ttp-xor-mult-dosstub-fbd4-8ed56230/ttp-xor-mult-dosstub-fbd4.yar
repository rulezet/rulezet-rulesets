rule TTP_XOR_MULT_DOSStub_fbd4 {
  strings:
    $key_fbd4 = { af bc [2] db a4 [2] 9c a6 [2] db b7 [2] 95 bb [2] 99 b1 [2] 8e ba [2] 95 f4 [2] a8 }

  condition:
    any of them
}