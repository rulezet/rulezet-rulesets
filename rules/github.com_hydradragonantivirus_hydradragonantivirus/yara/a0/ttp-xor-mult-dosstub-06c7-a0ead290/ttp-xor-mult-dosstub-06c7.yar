rule TTP_XOR_MULT_DOSStub_06c7 {
  strings:
    $key_06c7 = { 52 af [2] 26 b7 [2] 61 b5 [2] 26 a4 [2] 68 a8 [2] 64 a2 [2] 73 a9 [2] 68 e7 [2] 55 }

  condition:
    any of them
}