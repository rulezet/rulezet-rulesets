rule TTP_XOR_MULT_DOSStub_8743 {
  strings:
    $key_8743 = { d3 2b [2] a7 33 [2] e0 31 [2] a7 20 [2] e9 2c [2] e5 26 [2] f2 2d [2] e9 63 [2] d4 }

  condition:
    any of them
}