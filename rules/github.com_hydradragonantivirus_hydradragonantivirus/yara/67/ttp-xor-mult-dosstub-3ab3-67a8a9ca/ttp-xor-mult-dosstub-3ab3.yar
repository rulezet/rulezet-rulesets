rule TTP_XOR_MULT_DOSStub_3ab3 {
  strings:
    $key_3ab3 = { 6e db [2] 1a c3 [2] 5d c1 [2] 1a d0 [2] 54 dc [2] 58 d6 [2] 4f dd [2] 54 93 [2] 69 }

  condition:
    any of them
}