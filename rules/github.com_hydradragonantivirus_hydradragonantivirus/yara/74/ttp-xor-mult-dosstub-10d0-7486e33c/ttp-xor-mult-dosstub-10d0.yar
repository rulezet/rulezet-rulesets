rule TTP_XOR_MULT_DOSStub_10d0 {
  strings:
    $key_10d0 = { 44 b8 [2] 30 a0 [2] 77 a2 [2] 30 b3 [2] 7e bf [2] 72 b5 [2] 65 be [2] 7e f0 [2] 43 }

  condition:
    any of them
}