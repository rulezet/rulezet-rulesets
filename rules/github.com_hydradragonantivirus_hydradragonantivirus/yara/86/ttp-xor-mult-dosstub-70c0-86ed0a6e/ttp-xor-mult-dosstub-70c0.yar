rule TTP_XOR_MULT_DOSStub_70c0 {
  strings:
    $key_70c0 = { 24 a8 [2] 50 b0 [2] 17 b2 [2] 50 a3 [2] 1e af [2] 12 a5 [2] 05 ae [2] 1e e0 [2] 23 }

  condition:
    any of them
}