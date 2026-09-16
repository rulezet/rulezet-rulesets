rule TTP_XOR_MULT_DOSStub_0fb2 {
  strings:
    $key_0fb2 = { 5b da [2] 2f c2 [2] 68 c0 [2] 2f d1 [2] 61 dd [2] 6d d7 [2] 7a dc [2] 61 92 [2] 5c }

  condition:
    any of them
}