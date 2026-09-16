rule TTP_XOR_MULT_DOSStub_54d0 {
  strings:
    $key_54d0 = { 00 b8 [2] 74 a0 [2] 33 a2 [2] 74 b3 [2] 3a bf [2] 36 b5 [2] 21 be [2] 3a f0 [2] 07 }

  condition:
    any of them
}