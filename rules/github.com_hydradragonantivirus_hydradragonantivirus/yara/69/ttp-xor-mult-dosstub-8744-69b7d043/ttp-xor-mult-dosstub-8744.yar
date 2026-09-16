rule TTP_XOR_MULT_DOSStub_8744 {
  strings:
    $key_8744 = { d3 2c [2] a7 34 [2] e0 36 [2] a7 27 [2] e9 2b [2] e5 21 [2] f2 2a [2] e9 64 [2] d4 }

  condition:
    any of them
}