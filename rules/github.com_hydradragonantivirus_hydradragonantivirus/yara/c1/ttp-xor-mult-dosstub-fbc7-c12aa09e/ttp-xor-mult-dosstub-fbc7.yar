rule TTP_XOR_MULT_DOSStub_fbc7 {
  strings:
    $key_fbc7 = { af af [2] db b7 [2] 9c b5 [2] db a4 [2] 95 a8 [2] 99 a2 [2] 8e a9 [2] 95 e7 [2] a8 }

  condition:
    any of them
}