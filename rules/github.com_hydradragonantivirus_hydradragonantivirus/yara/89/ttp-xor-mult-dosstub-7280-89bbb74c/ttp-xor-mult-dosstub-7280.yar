rule TTP_XOR_MULT_DOSStub_7280 {
  strings:
    $key_7280 = { 26 e8 [2] 52 f0 [2] 15 f2 [2] 52 e3 [2] 1c ef [2] 10 e5 [2] 07 ee [2] 1c a0 [2] 21 }

  condition:
    any of them
}