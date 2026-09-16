rule TTP_XOR_MULT_DOSStub_6281 {
  strings:
    $key_6281 = { 36 e9 [2] 42 f1 [2] 05 f3 [2] 42 e2 [2] 0c ee [2] 00 e4 [2] 17 ef [2] 0c a1 [2] 31 }

  condition:
    any of them
}