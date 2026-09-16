rule TTP_XOR_MULT_DOSStub_dec3 {
  strings:
    $key_dec3 = { 8a ab [2] fe b3 [2] b9 b1 [2] fe a0 [2] b0 ac [2] bc a6 [2] ab ad [2] b0 e3 [2] 8d }

  condition:
    any of them
}