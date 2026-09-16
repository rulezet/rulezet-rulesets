rule TTP_XOR_MULT_DOSStub_b0f3 {
  strings:
    $key_b0f3 = { e4 9b [2] 90 83 [2] d7 81 [2] 90 90 [2] de 9c [2] d2 96 [2] c5 9d [2] de d3 [2] e3 }

  condition:
    any of them
}