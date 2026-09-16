rule TTP_XOR_MULT_DOSStub_3fb5 {
  strings:
    $key_3fb5 = { 6b dd [2] 1f c5 [2] 58 c7 [2] 1f d6 [2] 51 da [2] 5d d0 [2] 4a db [2] 51 95 [2] 6c }

  condition:
    any of them
}