rule TTP_XOR_MULT_DOSStub_15c7 {
  strings:
    $key_15c7 = { 41 af [2] 35 b7 [2] 72 b5 [2] 35 a4 [2] 7b a8 [2] 77 a2 [2] 60 a9 [2] 7b e7 [2] 46 }

  condition:
    any of them
}