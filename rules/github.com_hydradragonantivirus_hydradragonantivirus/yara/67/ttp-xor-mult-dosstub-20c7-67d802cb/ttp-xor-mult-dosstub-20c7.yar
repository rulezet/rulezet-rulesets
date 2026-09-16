rule TTP_XOR_MULT_DOSStub_20c7 {
  strings:
    $key_20c7 = { 74 af [2] 00 b7 [2] 47 b5 [2] 00 a4 [2] 4e a8 [2] 42 a2 [2] 55 a9 [2] 4e e7 [2] 73 }

  condition:
    any of them
}