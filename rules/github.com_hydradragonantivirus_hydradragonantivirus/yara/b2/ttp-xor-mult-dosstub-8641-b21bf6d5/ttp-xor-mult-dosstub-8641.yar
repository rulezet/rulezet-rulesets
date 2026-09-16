rule TTP_XOR_MULT_DOSStub_8641 {
  strings:
    $key_8641 = { d2 29 [2] a6 31 [2] e1 33 [2] a6 22 [2] e8 2e [2] e4 24 [2] f3 2f [2] e8 61 [2] d5 }

  condition:
    any of them
}