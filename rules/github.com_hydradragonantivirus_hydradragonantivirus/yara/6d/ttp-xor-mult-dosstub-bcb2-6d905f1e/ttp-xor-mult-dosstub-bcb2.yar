rule TTP_XOR_MULT_DOSStub_bcb2 {
  strings:
    $key_bcb2 = { e8 da [2] 9c c2 [2] db c0 [2] 9c d1 [2] d2 dd [2] de d7 [2] c9 dc [2] d2 92 [2] ef }

  condition:
    any of them
}