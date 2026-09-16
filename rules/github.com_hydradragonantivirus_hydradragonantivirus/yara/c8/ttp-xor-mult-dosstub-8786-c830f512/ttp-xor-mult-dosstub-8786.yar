rule TTP_XOR_MULT_DOSStub_8786 {
  strings:
    $key_8786 = { d3 ee [2] a7 f6 [2] e0 f4 [2] a7 e5 [2] e9 e9 [2] e5 e3 [2] f2 e8 [2] e9 a6 [2] d4 }

  condition:
    any of them
}