rule TTP_XOR_MULT_DOSStub_7ab3 {
  strings:
    $key_7ab3 = { 2e db [2] 5a c3 [2] 1d c1 [2] 5a d0 [2] 14 dc [2] 18 d6 [2] 0f dd [2] 14 93 [2] 29 }

  condition:
    any of them
}