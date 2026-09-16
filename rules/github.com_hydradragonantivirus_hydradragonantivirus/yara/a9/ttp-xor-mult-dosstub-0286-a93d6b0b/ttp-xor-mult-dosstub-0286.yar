rule TTP_XOR_MULT_DOSStub_0286 {
  strings:
    $key_0286 = { 56 ee [2] 22 f6 [2] 65 f4 [2] 22 e5 [2] 6c e9 [2] 60 e3 [2] 77 e8 [2] 6c a6 [2] 51 }

  condition:
    any of them
}