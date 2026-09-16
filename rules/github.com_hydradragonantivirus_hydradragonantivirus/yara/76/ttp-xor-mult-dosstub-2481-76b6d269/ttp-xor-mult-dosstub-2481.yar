rule TTP_XOR_MULT_DOSStub_2481 {
  strings:
    $key_2481 = { 70 e9 [2] 04 f1 [2] 43 f3 [2] 04 e2 [2] 4a ee [2] 46 e4 [2] 51 ef [2] 4a a1 [2] 77 }

  condition:
    any of them
}