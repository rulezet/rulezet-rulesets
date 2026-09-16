rule TTP_XOR_MULT_DOSStub_c881 {
  strings:
    $key_c881 = { 9c e9 [2] e8 f1 [2] af f3 [2] e8 e2 [2] a6 ee [2] aa e4 [2] bd ef [2] a6 a1 [2] 9b }

  condition:
    any of them
}