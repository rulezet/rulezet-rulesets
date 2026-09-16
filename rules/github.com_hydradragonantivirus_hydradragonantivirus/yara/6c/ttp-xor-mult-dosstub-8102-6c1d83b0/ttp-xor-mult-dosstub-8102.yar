rule TTP_XOR_MULT_DOSStub_8102 {
  strings:
    $key_8102 = { d5 6a [2] a1 72 [2] e6 70 [2] a1 61 [2] ef 6d [2] e3 67 [2] f4 6c [2] ef 22 [2] d2 }

  condition:
    any of them
}