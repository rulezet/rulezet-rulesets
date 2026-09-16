rule TTP_XOR_MULT_DOSStub_8b81 {
  strings:
    $key_8b81 = { df e9 [2] ab f1 [2] ec f3 [2] ab e2 [2] e5 ee [2] e9 e4 [2] fe ef [2] e5 a1 [2] d8 }

  condition:
    any of them
}