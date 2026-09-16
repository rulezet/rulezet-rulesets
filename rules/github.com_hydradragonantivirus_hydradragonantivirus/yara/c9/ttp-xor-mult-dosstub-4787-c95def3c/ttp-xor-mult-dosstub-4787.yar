rule TTP_XOR_MULT_DOSStub_4787 {
  strings:
    $key_4787 = { 13 ef [2] 67 f7 [2] 20 f5 [2] 67 e4 [2] 29 e8 [2] 25 e2 [2] 32 e9 [2] 29 a7 [2] 14 }

  condition:
    any of them
}