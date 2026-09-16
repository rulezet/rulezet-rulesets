rule TTP_XOR_MULT_DOSStub_8741 {
  strings:
    $key_8741 = { d3 29 [2] a7 31 [2] e0 33 [2] a7 22 [2] e9 2e [2] e5 24 [2] f2 2f [2] e9 61 [2] d4 }

  condition:
    any of them
}