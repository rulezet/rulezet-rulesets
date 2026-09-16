rule TTP_XOR_MULT_DOSStub_4281 {
  strings:
    $key_4281 = { 16 e9 [2] 62 f1 [2] 25 f3 [2] 62 e2 [2] 2c ee [2] 20 e4 [2] 37 ef [2] 2c a1 [2] 11 }

  condition:
    any of them
}