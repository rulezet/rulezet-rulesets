rule TTP_XOR_MULT_DOSStub_bcb4 {
  strings:
    $key_bcb4 = { e8 dc [2] 9c c4 [2] db c6 [2] 9c d7 [2] d2 db [2] de d1 [2] c9 da [2] d2 94 [2] ef }

  condition:
    any of them
}