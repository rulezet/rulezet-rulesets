rule TTP_XOR_MULT_DOSStub_7fb2 {
  strings:
    $key_7fb2 = { 2b da [2] 5f c2 [2] 18 c0 [2] 5f d1 [2] 11 dd [2] 1d d7 [2] 0a dc [2] 11 92 [2] 2c }

  condition:
    any of them
}