rule TTP_XOR_MULT_DOSStub_1fb5 {
  strings:
    $key_1fb5 = { 4b dd [2] 3f c5 [2] 78 c7 [2] 3f d6 [2] 71 da [2] 7d d0 [2] 6a db [2] 71 95 [2] 4c }

  condition:
    any of them
}