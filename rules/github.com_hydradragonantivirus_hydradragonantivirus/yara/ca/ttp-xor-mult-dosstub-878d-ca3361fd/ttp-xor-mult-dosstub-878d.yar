rule TTP_XOR_MULT_DOSStub_878d {
  strings:
    $key_878d = { d3 e5 [2] a7 fd [2] e0 ff [2] a7 ee [2] e9 e2 [2] e5 e8 [2] f2 e3 [2] e9 ad [2] d4 }

  condition:
    any of them
}