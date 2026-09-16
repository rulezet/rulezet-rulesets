rule TTP_XOR_MULT_DOSStub_7481 {
  strings:
    $key_7481 = { 20 e9 [2] 54 f1 [2] 13 f3 [2] 54 e2 [2] 1a ee [2] 16 e4 [2] 01 ef [2] 1a a1 [2] 27 }

  condition:
    any of them
}