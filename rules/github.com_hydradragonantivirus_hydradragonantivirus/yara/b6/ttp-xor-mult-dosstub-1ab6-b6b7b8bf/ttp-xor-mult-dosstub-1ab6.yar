rule TTP_XOR_MULT_DOSStub_1ab6 {
  strings:
    $key_1ab6 = { 4e de [2] 3a c6 [2] 7d c4 [2] 3a d5 [2] 74 d9 [2] 78 d3 [2] 6f d8 [2] 74 96 [2] 49 }

  condition:
    any of them
}