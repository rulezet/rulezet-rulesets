rule TTP_XOR_MULT_DOSStub_813c {
  strings:
    $key_813c = { d5 54 [2] a1 4c [2] e6 4e [2] a1 5f [2] ef 53 [2] e3 59 [2] f4 52 [2] ef 1c [2] d2 }

  condition:
    any of them
}