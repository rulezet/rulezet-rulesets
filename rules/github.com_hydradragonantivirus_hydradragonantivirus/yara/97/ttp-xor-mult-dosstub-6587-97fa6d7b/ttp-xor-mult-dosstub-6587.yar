rule TTP_XOR_MULT_DOSStub_6587 {
  strings:
    $key_6587 = { 31 ef [2] 45 f7 [2] 02 f5 [2] 45 e4 [2] 0b e8 [2] 07 e2 [2] 10 e9 [2] 0b a7 [2] 36 }

  condition:
    any of them
}