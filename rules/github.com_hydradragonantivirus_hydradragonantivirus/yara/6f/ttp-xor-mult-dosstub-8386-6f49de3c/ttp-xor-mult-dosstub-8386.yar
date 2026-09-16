rule TTP_XOR_MULT_DOSStub_8386 {
  strings:
    $key_8386 = { d7 ee [2] a3 f6 [2] e4 f4 [2] a3 e5 [2] ed e9 [2] e1 e3 [2] f6 e8 [2] ed a6 [2] d0 }

  condition:
    any of them
}