rule TTP_XOR_MULT_DOSStub_20b2 {
  strings:
    $key_20b2 = { 74 da [2] 00 c2 [2] 47 c0 [2] 00 d1 [2] 4e dd [2] 42 d7 [2] 55 dc [2] 4e 92 [2] 73 }

  condition:
    any of them
}