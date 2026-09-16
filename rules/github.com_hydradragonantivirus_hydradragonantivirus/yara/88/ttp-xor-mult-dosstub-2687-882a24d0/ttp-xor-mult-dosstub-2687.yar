rule TTP_XOR_MULT_DOSStub_2687 {
  strings:
    $key_2687 = { 72 ef [2] 06 f7 [2] 41 f5 [2] 06 e4 [2] 48 e8 [2] 44 e2 [2] 53 e9 [2] 48 a7 [2] 75 }

  condition:
    any of them
}