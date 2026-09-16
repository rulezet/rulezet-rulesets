rule TTP_XOR_MULT_DOSStub_6fb3 {
  strings:
    $key_6fb3 = { 3b db [2] 4f c3 [2] 08 c1 [2] 4f d0 [2] 01 dc [2] 0d d6 [2] 1a dd [2] 01 93 [2] 3c }

  condition:
    any of them
}