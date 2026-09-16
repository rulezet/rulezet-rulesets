rule TTP_XOR_MULT_DOSStub_1980 {
  strings:
    $key_1980 = { 4d e8 [2] 39 f0 [2] 7e f2 [2] 39 e3 [2] 77 ef [2] 7b e5 [2] 6c ee [2] 77 a0 [2] 4a }

  condition:
    any of them
}