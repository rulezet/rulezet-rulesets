rule TTP_XOR_MULT_DOSStub_0980 {
  strings:
    $key_0980 = { 5d e8 [2] 29 f0 [2] 6e f2 [2] 29 e3 [2] 67 ef [2] 6b e5 [2] 7c ee [2] 67 a0 [2] 5a }

  condition:
    any of them
}