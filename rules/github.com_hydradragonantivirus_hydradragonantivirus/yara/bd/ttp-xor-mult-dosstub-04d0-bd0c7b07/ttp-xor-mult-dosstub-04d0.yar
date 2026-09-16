rule TTP_XOR_MULT_DOSStub_04d0 {
  strings:
    $key_04d0 = { 50 b8 [2] 24 a0 [2] 63 a2 [2] 24 b3 [2] 6a bf [2] 66 b5 [2] 71 be [2] 6a f0 [2] 57 }

  condition:
    any of them
}