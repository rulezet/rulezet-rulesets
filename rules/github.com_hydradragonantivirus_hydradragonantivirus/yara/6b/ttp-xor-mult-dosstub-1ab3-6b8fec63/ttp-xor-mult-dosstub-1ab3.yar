rule TTP_XOR_MULT_DOSStub_1ab3 {
  strings:
    $key_1ab3 = { 4e db [2] 3a c3 [2] 7d c1 [2] 3a d0 [2] 74 dc [2] 78 d6 [2] 6f dd [2] 74 93 [2] 49 }

  condition:
    any of them
}