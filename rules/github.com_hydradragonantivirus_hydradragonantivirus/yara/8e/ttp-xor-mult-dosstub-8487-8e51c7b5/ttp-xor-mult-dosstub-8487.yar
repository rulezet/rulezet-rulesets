rule TTP_XOR_MULT_DOSStub_8487 {
  strings:
    $key_8487 = { d0 ef [2] a4 f7 [2] e3 f5 [2] a4 e4 [2] ea e8 [2] e6 e2 [2] f1 e9 [2] ea a7 [2] d7 }

  condition:
    any of them
}