rule TTP_XOR_MULT_DOSStub_87ce {
  strings:
    $key_87ce = { d3 a6 [2] a7 be [2] e0 bc [2] a7 ad [2] e9 a1 [2] e5 ab [2] f2 a0 [2] e9 ee [2] d4 }

  condition:
    any of them
}