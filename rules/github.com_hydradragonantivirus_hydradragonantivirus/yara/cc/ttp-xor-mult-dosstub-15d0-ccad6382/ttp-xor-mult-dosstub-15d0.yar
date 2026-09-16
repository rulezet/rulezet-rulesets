rule TTP_XOR_MULT_DOSStub_15d0 {
  strings:
    $key_15d0 = { 41 b8 [2] 35 a0 [2] 72 a2 [2] 35 b3 [2] 7b bf [2] 77 b5 [2] 60 be [2] 7b f0 [2] 46 }

  condition:
    any of them
}