rule TTP_XOR_MULT_DOSStub_dec1 {
  strings:
    $key_dec1 = { 8a a9 [2] fe b1 [2] b9 b3 [2] fe a2 [2] b0 ae [2] bc a4 [2] ab af [2] b0 e1 [2] 8d }

  condition:
    any of them
}