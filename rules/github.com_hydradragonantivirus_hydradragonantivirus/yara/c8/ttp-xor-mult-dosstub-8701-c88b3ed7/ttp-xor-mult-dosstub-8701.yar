rule TTP_XOR_MULT_DOSStub_8701 {
  strings:
    $key_8701 = { d3 69 [2] a7 71 [2] e0 73 [2] a7 62 [2] e9 6e [2] e5 64 [2] f2 6f [2] e9 21 [2] d4 }

  condition:
    any of them
}