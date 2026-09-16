rule TTP_XOR_MULT_DOSStub_0fb5 {
  strings:
    $key_0fb5 = { 5b dd [2] 2f c5 [2] 68 c7 [2] 2f d6 [2] 61 da [2] 6d d0 [2] 7a db [2] 61 95 [2] 5c }

  condition:
    any of them
}