rule TTP_XOR_MULT_DOSStub_8d3e {
  strings:
    $key_8d3e = { d9 56 [2] ad 4e [2] ea 4c [2] ad 5d [2] e3 51 [2] ef 5b [2] f8 50 [2] e3 1e [2] de }

  condition:
    any of them
}