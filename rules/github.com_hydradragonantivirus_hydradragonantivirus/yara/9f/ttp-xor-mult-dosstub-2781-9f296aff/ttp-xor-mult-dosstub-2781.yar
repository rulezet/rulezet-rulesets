rule TTP_XOR_MULT_DOSStub_2781 {
  strings:
    $key_2781 = { 73 e9 [2] 07 f1 [2] 40 f3 [2] 07 e2 [2] 49 ee [2] 45 e4 [2] 52 ef [2] 49 a1 [2] 74 }

  condition:
    any of them
}