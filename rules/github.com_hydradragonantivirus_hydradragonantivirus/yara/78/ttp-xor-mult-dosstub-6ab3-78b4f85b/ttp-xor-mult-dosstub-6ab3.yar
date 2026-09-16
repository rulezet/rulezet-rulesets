rule TTP_XOR_MULT_DOSStub_6ab3 {
  strings:
    $key_6ab3 = { 3e db [2] 4a c3 [2] 0d c1 [2] 4a d0 [2] 04 dc [2] 08 d6 [2] 1f dd [2] 04 93 [2] 39 }

  condition:
    any of them
}