rule TTP_XOR_MULT_DOSStub_8461 {
  strings:
    $key_8461 = { d0 09 [2] a4 11 [2] e3 13 [2] a4 02 [2] ea 0e [2] e6 04 [2] f1 0f [2] ea 41 [2] d7 }

  condition:
    any of them
}