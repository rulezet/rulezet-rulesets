rule TTP_XOR_MULT_DOSStub_4db3 {
  strings:
    $key_4db3 = { 19 db [2] 6d c3 [2] 2a c1 [2] 6d d0 [2] 23 dc [2] 2f d6 [2] 38 dd [2] 23 93 [2] 1e }

  condition:
    any of them
}