rule TTP_XOR_MULT_DOSStub_5416 {
  strings:
    $key_5416 = { 00 7e [2] 74 66 [2] 33 64 [2] 74 75 [2] 3a 79 [2] 36 73 [2] 21 78 [2] 3a 36 [2] 07 }

  condition:
    any of them
}