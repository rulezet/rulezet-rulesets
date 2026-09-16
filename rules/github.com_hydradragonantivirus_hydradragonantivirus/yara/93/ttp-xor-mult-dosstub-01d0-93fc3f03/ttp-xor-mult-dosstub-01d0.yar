rule TTP_XOR_MULT_DOSStub_01d0 {
  strings:
    $key_01d0 = { 55 b8 [2] 21 a0 [2] 66 a2 [2] 21 b3 [2] 6f bf [2] 63 b5 [2] 74 be [2] 6f f0 [2] 52 }

  condition:
    any of them
}