rule TTP_XOR_MULT_DOSStub_fbc2 {
  strings:
    $key_fbc2 = { af aa [2] db b2 [2] 9c b0 [2] db a1 [2] 95 ad [2] 99 a7 [2] 8e ac [2] 95 e2 [2] a8 }

  condition:
    any of them
}