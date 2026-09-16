rule TTP_XOR_MULT_DOSStub_8370 {
  strings:
    $key_8370 = { d7 18 [2] a3 00 [2] e4 02 [2] a3 13 [2] ed 1f [2] e1 15 [2] f6 1e [2] ed 50 [2] d0 }

  condition:
    any of them
}