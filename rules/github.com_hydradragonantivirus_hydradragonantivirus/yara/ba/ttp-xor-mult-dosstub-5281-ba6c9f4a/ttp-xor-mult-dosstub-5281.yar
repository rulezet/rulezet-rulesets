rule TTP_XOR_MULT_DOSStub_5281 {
  strings:
    $key_5281 = { 06 e9 [2] 72 f1 [2] 35 f3 [2] 72 e2 [2] 3c ee [2] 30 e4 [2] 27 ef [2] 3c a1 [2] 01 }

  condition:
    any of them
}