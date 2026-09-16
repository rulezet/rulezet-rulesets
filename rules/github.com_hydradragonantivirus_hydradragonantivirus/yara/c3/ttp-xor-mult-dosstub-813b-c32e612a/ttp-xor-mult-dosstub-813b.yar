rule TTP_XOR_MULT_DOSStub_813b {
  strings:
    $key_813b = { d5 53 [2] a1 4b [2] e6 49 [2] a1 58 [2] ef 54 [2] e3 5e [2] f4 55 [2] ef 1b [2] d2 }

  condition:
    any of them
}