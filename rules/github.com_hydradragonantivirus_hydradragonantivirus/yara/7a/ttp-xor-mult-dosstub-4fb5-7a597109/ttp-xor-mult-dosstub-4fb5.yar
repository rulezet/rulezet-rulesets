rule TTP_XOR_MULT_DOSStub_4fb5 {
  strings:
    $key_4fb5 = { 1b dd [2] 6f c5 [2] 28 c7 [2] 6f d6 [2] 21 da [2] 2d d0 [2] 3a db [2] 21 95 [2] 1c }

  condition:
    any of them
}