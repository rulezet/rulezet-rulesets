rule TTP_XOR_MULT_DOSStub_8376 {
  strings:
    $key_8376 = { d7 1e [2] a3 06 [2] e4 04 [2] a3 15 [2] ed 19 [2] e1 13 [2] f6 18 [2] ed 56 [2] d0 }

  condition:
    any of them
}