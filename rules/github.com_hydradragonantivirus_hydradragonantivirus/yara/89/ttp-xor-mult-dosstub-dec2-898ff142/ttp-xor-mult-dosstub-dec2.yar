rule TTP_XOR_MULT_DOSStub_dec2 {
  strings:
    $key_dec2 = { 8a aa [2] fe b2 [2] b9 b0 [2] fe a1 [2] b0 ad [2] bc a7 [2] ab ac [2] b0 e2 [2] 8d }

  condition:
    any of them
}