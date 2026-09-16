rule TTP_XOR_MULT_DOSStub_6280 {
  strings:
    $key_6280 = { 36 e8 [2] 42 f0 [2] 05 f2 [2] 42 e3 [2] 0c ef [2] 00 e5 [2] 17 ee [2] 0c a0 [2] 31 }

  condition:
    any of them
}