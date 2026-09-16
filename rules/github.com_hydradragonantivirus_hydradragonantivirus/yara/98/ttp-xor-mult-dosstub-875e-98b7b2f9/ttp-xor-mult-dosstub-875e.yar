rule TTP_XOR_MULT_DOSStub_875e {
  strings:
    $key_875e = { d3 36 [2] a7 2e [2] e0 2c [2] a7 3d [2] e9 31 [2] e5 3b [2] f2 30 [2] e9 7e [2] d4 }

  condition:
    any of them
}