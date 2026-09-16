rule TTP_XOR_MULT_DOSStub_8470 {
  strings:
    $key_8470 = { d0 18 [2] a4 00 [2] e3 02 [2] a4 13 [2] ea 1f [2] e6 15 [2] f1 1e [2] ea 50 [2] d7 }

  condition:
    any of them
}