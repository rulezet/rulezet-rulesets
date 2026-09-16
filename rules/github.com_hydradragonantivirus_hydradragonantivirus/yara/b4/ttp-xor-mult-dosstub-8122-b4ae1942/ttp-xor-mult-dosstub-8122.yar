rule TTP_XOR_MULT_DOSStub_8122 {
  strings:
    $key_8122 = { d5 4a [2] a1 52 [2] e6 50 [2] a1 41 [2] ef 4d [2] e3 47 [2] f4 4c [2] ef 02 [2] d2 }

  condition:
    any of them
}