rule TTP_XOR_MULT_DOSStub_817c {
  strings:
    $key_817c = { d5 14 [2] a1 0c [2] e6 0e [2] a1 1f [2] ef 13 [2] e3 19 [2] f4 12 [2] ef 5c [2] d2 }

  condition:
    any of them
}