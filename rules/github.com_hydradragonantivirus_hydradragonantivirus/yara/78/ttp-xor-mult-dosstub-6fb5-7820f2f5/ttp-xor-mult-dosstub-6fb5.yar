rule TTP_XOR_MULT_DOSStub_6fb5 {
  strings:
    $key_6fb5 = { 3b dd [2] 4f c5 [2] 08 c7 [2] 4f d6 [2] 01 da [2] 0d d0 [2] 1a db [2] 01 95 [2] 3c }

  condition:
    any of them
}