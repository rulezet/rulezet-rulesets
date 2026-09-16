rule TTP_XOR_MULT_DOSStub_41d0 {
  strings:
    $key_41d0 = { 15 b8 [2] 61 a0 [2] 26 a2 [2] 61 b3 [2] 2f bf [2] 23 b5 [2] 34 be [2] 2f f0 [2] 12 }

  condition:
    any of them
}