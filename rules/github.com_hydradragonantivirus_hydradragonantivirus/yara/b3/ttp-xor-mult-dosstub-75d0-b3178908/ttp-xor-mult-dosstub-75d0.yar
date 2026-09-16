rule TTP_XOR_MULT_DOSStub_75d0 {
  strings:
    $key_75d0 = { 21 b8 [2] 55 a0 [2] 12 a2 [2] 55 b3 [2] 1b bf [2] 17 b5 [2] 00 be [2] 1b f0 [2] 26 }

  condition:
    any of them
}