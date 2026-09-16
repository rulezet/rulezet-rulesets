rule TTP_XOR_MULT_DOSStub_8420 {
  strings:
    $key_8420 = { d0 48 [2] a4 50 [2] e3 52 [2] a4 43 [2] ea 4f [2] e6 45 [2] f1 4e [2] ea 00 [2] d7 }

  condition:
    any of them
}