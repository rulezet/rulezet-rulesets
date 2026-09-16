rule TTP_XOR_MULT_DOSStub_2487 {
  strings:
    $key_2487 = { 70 ef [2] 04 f7 [2] 43 f5 [2] 04 e4 [2] 4a e8 [2] 46 e2 [2] 51 e9 [2] 4a a7 [2] 77 }

  condition:
    any of them
}