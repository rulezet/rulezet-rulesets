rule TTP_XOR_MULT_DOSStub_15d6 {
  strings:
    $key_15d6 = { 41 be [2] 35 a6 [2] 72 a4 [2] 35 b5 [2] 7b b9 [2] 77 b3 [2] 60 b8 [2] 7b f6 [2] 46 }

  condition:
    any of them
}