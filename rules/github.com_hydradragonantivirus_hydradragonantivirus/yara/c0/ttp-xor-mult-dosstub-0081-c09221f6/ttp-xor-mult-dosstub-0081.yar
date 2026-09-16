rule TTP_XOR_MULT_DOSStub_0081 {
  strings:
    $key_0081 = { 54 e9 [2] 20 f1 [2] 67 f3 [2] 20 e2 [2] 6e ee [2] 62 e4 [2] 75 ef [2] 6e a1 [2] 53 }

  condition:
    any of them
}