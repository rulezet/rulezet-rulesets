rule TTP_XOR_MULT_DOSStub_37c7 {
  strings:
    $key_37c7 = { 63 af [2] 17 b7 [2] 50 b5 [2] 17 a4 [2] 59 a8 [2] 55 a2 [2] 42 a9 [2] 59 e7 [2] 64 }

  condition:
    any of them
}