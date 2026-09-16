rule TTP_XOR_MULT_DOSStub_8441 {
  strings:
    $key_8441 = { d0 29 [2] a4 31 [2] e3 33 [2] a4 22 [2] ea 2e [2] e6 24 [2] f1 2f [2] ea 61 [2] d7 }

  condition:
    any of them
}