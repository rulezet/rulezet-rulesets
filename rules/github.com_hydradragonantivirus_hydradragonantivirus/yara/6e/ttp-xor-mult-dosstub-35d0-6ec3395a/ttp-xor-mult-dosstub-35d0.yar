rule TTP_XOR_MULT_DOSStub_35d0 {
  strings:
    $key_35d0 = { 61 b8 [2] 15 a0 [2] 52 a2 [2] 15 b3 [2] 5b bf [2] 57 b5 [2] 40 be [2] 5b f0 [2] 66 }

  condition:
    any of them
}