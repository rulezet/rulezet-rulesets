rule TTP_XOR_MULT_DOSStub_815e {
  strings:
    $key_815e = { d5 36 [2] a1 2e [2] e6 2c [2] a1 3d [2] ef 31 [2] e3 3b [2] f4 30 [2] ef 7e [2] d2 }

  condition:
    any of them
}