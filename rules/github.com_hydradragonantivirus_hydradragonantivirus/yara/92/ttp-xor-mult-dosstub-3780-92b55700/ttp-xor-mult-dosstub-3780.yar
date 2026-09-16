rule TTP_XOR_MULT_DOSStub_3780 {
  strings:
    $key_3780 = { 63 e8 [2] 17 f0 [2] 50 f2 [2] 17 e3 [2] 59 ef [2] 55 e5 [2] 42 ee [2] 59 a0 [2] 64 }

  condition:
    any of them
}