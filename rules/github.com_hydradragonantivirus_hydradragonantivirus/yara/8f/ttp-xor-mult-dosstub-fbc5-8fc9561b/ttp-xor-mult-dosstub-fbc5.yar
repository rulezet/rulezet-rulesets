rule TTP_XOR_MULT_DOSStub_fbc5 {
  strings:
    $key_fbc5 = { af ad [2] db b5 [2] 9c b7 [2] db a6 [2] 95 aa [2] 99 a0 [2] 8e ab [2] 95 e5 [2] a8 }

  condition:
    any of them
}