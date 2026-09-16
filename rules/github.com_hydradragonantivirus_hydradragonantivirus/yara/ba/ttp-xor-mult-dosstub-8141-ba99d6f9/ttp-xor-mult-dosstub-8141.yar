rule TTP_XOR_MULT_DOSStub_8141 {
  strings:
    $key_8141 = { d5 29 [2] a1 31 [2] e6 33 [2] a1 22 [2] ef 2e [2] e3 24 [2] f4 2f [2] ef 61 [2] d2 }

  condition:
    any of them
}