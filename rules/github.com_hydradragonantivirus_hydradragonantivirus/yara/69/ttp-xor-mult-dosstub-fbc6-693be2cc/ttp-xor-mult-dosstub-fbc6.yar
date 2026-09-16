rule TTP_XOR_MULT_DOSStub_fbc6 {
  strings:
    $key_fbc6 = { af ae [2] db b6 [2] 9c b4 [2] db a5 [2] 95 a9 [2] 99 a3 [2] 8e a8 [2] 95 e6 [2] a8 }

  condition:
    any of them
}