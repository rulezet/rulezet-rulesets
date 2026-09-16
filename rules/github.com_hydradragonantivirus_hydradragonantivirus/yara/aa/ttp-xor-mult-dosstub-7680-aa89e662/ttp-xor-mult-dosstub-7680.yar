rule TTP_XOR_MULT_DOSStub_7680 {
  strings:
    $key_7680 = { 22 e8 [2] 56 f0 [2] 11 f2 [2] 56 e3 [2] 18 ef [2] 14 e5 [2] 03 ee [2] 18 a0 [2] 25 }

  condition:
    any of them
}