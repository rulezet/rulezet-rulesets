rule TTP_XOR_MULT_DOSStub_2980 {
  strings:
    $key_2980 = { 7d e8 [2] 09 f0 [2] 4e f2 [2] 09 e3 [2] 47 ef [2] 4b e5 [2] 5c ee [2] 47 a0 [2] 7a }

  condition:
    any of them
}