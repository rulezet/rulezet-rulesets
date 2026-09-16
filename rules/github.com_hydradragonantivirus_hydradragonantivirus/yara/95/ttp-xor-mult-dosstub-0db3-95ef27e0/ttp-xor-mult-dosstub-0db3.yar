rule TTP_XOR_MULT_DOSStub_0db3 {
  strings:
    $key_0db3 = { 59 db [2] 2d c3 [2] 6a c1 [2] 2d d0 [2] 63 dc [2] 6f d6 [2] 78 dd [2] 63 93 [2] 5e }

  condition:
    any of them
}