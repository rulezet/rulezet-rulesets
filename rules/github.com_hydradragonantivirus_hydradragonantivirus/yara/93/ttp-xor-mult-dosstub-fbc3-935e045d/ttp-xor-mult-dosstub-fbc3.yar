rule TTP_XOR_MULT_DOSStub_fbc3 {
  strings:
    $key_fbc3 = { af ab [2] db b3 [2] 9c b1 [2] db a0 [2] 95 ac [2] 99 a6 [2] 8e ad [2] 95 e3 [2] a8 }

  condition:
    any of them
}