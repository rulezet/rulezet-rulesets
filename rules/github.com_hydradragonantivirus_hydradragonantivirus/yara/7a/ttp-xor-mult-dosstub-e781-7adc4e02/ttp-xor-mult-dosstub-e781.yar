rule TTP_XOR_MULT_DOSStub_e781 {
  strings:
    $key_e781 = { b3 e9 [2] c7 f1 [2] 80 f3 [2] c7 e2 [2] 89 ee [2] 85 e4 [2] 92 ef [2] 89 a1 [2] b4 }

  condition:
    any of them
}