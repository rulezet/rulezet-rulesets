rule TTP_XOR_MULT_DOSStub_6081 {
  strings:
    $key_6081 = { 34 e9 [2] 40 f1 [2] 07 f3 [2] 40 e2 [2] 0e ee [2] 02 e4 [2] 15 ef [2] 0e a1 [2] 33 }

  condition:
    any of them
}