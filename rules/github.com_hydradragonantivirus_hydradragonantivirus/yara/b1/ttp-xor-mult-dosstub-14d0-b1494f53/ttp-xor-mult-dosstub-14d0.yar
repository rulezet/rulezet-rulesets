rule TTP_XOR_MULT_DOSStub_14d0 {
  strings:
    $key_14d0 = { 40 b8 [2] 34 a0 [2] 73 a2 [2] 34 b3 [2] 7a bf [2] 76 b5 [2] 61 be [2] 7a f0 [2] 47 }

  condition:
    any of them
}