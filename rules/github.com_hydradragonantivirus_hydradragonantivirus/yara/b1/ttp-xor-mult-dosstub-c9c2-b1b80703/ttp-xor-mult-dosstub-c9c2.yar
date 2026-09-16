rule TTP_XOR_MULT_DOSStub_c9c2 {
  strings:
    $key_c9c2 = { 9d aa [2] e9 b2 [2] ae b0 [2] e9 a1 [2] a7 ad [2] ab a7 [2] bc ac [2] a7 e2 [2] 9a }

  condition:
    any of them
}