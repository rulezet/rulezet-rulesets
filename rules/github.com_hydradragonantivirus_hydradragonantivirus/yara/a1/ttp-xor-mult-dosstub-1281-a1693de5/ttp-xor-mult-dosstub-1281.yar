rule TTP_XOR_MULT_DOSStub_1281 {
  strings:
    $key_1281 = { 46 e9 [2] 32 f1 [2] 75 f3 [2] 32 e2 [2] 7c ee [2] 70 e4 [2] 67 ef [2] 7c a1 [2] 41 }

  condition:
    any of them
}