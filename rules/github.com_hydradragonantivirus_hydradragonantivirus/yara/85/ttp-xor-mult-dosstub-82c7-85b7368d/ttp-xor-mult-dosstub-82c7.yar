rule TTP_XOR_MULT_DOSStub_82c7 {
  strings:
    $key_82c7 = { d6 af [2] a2 b7 [2] e5 b5 [2] a2 a4 [2] ec a8 [2] e0 a2 [2] f7 a9 [2] ec e7 [2] d1 }

  condition:
    any of them
}