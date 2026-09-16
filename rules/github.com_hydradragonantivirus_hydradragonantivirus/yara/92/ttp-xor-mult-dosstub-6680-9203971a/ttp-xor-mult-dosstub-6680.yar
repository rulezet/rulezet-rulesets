rule TTP_XOR_MULT_DOSStub_6680 {
  strings:
    $key_6680 = { 32 e8 [2] 46 f0 [2] 01 f2 [2] 46 e3 [2] 08 ef [2] 04 e5 [2] 13 ee [2] 08 a0 [2] 35 }

  condition:
    any of them
}