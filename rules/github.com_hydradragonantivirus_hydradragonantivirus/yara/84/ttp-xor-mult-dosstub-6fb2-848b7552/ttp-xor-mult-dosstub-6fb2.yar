rule TTP_XOR_MULT_DOSStub_6fb2 {
  strings:
    $key_6fb2 = { 3b da [2] 4f c2 [2] 08 c0 [2] 4f d1 [2] 01 dd [2] 0d d7 [2] 1a dc [2] 01 92 [2] 3c }

  condition:
    any of them
}