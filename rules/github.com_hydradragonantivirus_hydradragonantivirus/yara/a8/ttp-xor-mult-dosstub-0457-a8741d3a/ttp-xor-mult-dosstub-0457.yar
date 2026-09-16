rule TTP_XOR_MULT_DOSStub_0457 {
  strings:
    $key_0457 = { 50 3f [2] 24 27 [2] 63 25 [2] 24 34 [2] 6a 38 [2] 66 32 [2] 71 39 [2] 6a 77 [2] 57 }

  condition:
    any of them
}