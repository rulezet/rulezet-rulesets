rule TTP_XOR_MULT_DOSStub_8626 {
  strings:
    $key_8626 = { d2 4e [2] a6 56 [2] e1 54 [2] a6 45 [2] e8 49 [2] e4 43 [2] f3 48 [2] e8 06 [2] d5 }

  condition:
    any of them
}