rule TTP_XOR_MULT_DOSStub_8437 {
  strings:
    $key_8437 = { d0 5f [2] a4 47 [2] e3 45 [2] a4 54 [2] ea 58 [2] e6 52 [2] f1 59 [2] ea 17 [2] d7 }

  condition:
    any of them
}