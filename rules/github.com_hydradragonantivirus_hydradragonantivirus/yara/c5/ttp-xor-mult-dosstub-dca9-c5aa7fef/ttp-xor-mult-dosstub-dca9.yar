rule TTP_XOR_MULT_DOSStub_dca9 {
  strings:
    $key_dca9 = { 88 c1 [2] fc d9 [2] bb db [2] fc ca [2] b2 c6 [2] be cc [2] a9 c7 [2] b2 89 [2] 8f }

  condition:
    any of them
}