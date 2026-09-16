rule TTP_XOR_MULT_DOSStub_3480 {
  strings:
    $key_3480 = { 60 e8 [2] 14 f0 [2] 53 f2 [2] 14 e3 [2] 5a ef [2] 56 e5 [2] 41 ee [2] 5a a0 [2] 67 }

  condition:
    any of them
}