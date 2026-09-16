rule TTP_XOR_MULT_DOSStub_8481 {
  strings:
    $key_8481 = { d0 e9 [2] a4 f1 [2] e3 f3 [2] a4 e2 [2] ea ee [2] e6 e4 [2] f1 ef [2] ea a1 [2] d7 }

  condition:
    any of them
}