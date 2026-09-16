rule TTP_XOR_MULT_DOSStub_8d3b {
  strings:
    $key_8d3b = { d9 53 [2] ad 4b [2] ea 49 [2] ad 58 [2] e3 54 [2] ef 5e [2] f8 55 [2] e3 1b [2] de }

  condition:
    any of them
}