rule TTP_XOR_MULT_DOSStub_0281 {
  strings:
    $key_0281 = { 56 e9 [2] 22 f1 [2] 65 f3 [2] 22 e2 [2] 6c ee [2] 60 e4 [2] 77 ef [2] 6c a1 [2] 51 }

  condition:
    any of them
}