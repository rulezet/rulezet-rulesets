rule TTP_XOR_MULT_DOSStub_8d3d {
  strings:
    $key_8d3d = { d9 55 [2] ad 4d [2] ea 4f [2] ad 5e [2] e3 52 [2] ef 58 [2] f8 53 [2] e3 1d [2] de }

  condition:
    any of them
}