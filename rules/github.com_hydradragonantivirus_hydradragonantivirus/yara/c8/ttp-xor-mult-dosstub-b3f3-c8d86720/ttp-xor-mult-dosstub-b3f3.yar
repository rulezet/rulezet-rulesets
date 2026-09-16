rule TTP_XOR_MULT_DOSStub_b3f3 {
  strings:
    $key_b3f3 = { e7 9b [2] 93 83 [2] d4 81 [2] 93 90 [2] dd 9c [2] d1 96 [2] c6 9d [2] dd d3 [2] e0 }

  condition:
    any of them
}