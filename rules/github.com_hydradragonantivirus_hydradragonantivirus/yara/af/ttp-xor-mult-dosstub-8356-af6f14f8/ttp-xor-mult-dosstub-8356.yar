rule TTP_XOR_MULT_DOSStub_8356 {
  strings:
    $key_8356 = { d7 3e [2] a3 26 [2] e4 24 [2] a3 35 [2] ed 39 [2] e1 33 [2] f6 38 [2] ed 76 [2] d0 }

  condition:
    any of them
}