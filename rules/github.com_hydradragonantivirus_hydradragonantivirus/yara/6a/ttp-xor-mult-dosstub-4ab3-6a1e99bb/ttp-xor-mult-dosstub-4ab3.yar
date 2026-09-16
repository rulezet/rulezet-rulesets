rule TTP_XOR_MULT_DOSStub_4ab3 {
  strings:
    $key_4ab3 = { 1e db [2] 6a c3 [2] 2d c1 [2] 6a d0 [2] 24 dc [2] 28 d6 [2] 3f dd [2] 24 93 [2] 19 }

  condition:
    any of them
}