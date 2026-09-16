rule TTP_XOR_MULT_DOSStub_3787 {
  strings:
    $key_3787 = { 63 ef [2] 17 f7 [2] 50 f5 [2] 17 e4 [2] 59 e8 [2] 55 e2 [2] 42 e9 [2] 59 a7 [2] 64 }

  condition:
    any of them
}