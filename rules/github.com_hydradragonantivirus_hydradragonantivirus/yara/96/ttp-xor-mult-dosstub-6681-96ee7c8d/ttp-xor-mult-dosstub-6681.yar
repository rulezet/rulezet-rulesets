rule TTP_XOR_MULT_DOSStub_6681 {
  strings:
    $key_6681 = { 32 e9 [2] 46 f1 [2] 01 f3 [2] 46 e2 [2] 08 ee [2] 04 e4 [2] 13 ef [2] 08 a1 [2] 35 }

  condition:
    any of them
}