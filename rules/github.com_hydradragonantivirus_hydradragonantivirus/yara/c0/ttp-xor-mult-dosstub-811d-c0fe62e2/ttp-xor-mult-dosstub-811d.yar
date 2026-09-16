rule TTP_XOR_MULT_DOSStub_811d {
  strings:
    $key_811d = { d5 75 [2] a1 6d [2] e6 6f [2] a1 7e [2] ef 72 [2] e3 78 [2] f4 73 [2] ef 3d [2] d2 }

  condition:
    any of them
}