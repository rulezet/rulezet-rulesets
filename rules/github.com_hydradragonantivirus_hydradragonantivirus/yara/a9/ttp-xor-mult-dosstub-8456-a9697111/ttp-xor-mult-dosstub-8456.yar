rule TTP_XOR_MULT_DOSStub_8456 {
  strings:
    $key_8456 = { d0 3e [2] a4 26 [2] e3 24 [2] a4 35 [2] ea 39 [2] e6 33 [2] f1 38 [2] ea 76 [2] d7 }

  condition:
    any of them
}