rule TTP_XOR_MULT_DOSStub_c2a6 {
  strings:
    $key_c2a6 = { 96 ce [2] e2 d6 [2] a5 d4 [2] e2 c5 [2] ac c9 [2] a0 c3 [2] b7 c8 [2] ac 86 [2] 91 }

  condition:
    any of them
}