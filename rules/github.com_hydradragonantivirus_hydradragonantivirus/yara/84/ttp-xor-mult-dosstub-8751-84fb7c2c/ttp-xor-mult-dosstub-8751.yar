rule TTP_XOR_MULT_DOSStub_8751 {
  strings:
    $key_8751 = { d3 39 [2] a7 21 [2] e0 23 [2] a7 32 [2] e9 3e [2] e5 34 [2] f2 3f [2] e9 71 [2] d4 }

  condition:
    any of them
}