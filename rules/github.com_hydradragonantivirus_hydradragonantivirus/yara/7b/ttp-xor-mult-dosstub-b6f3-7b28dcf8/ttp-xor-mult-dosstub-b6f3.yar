rule TTP_XOR_MULT_DOSStub_b6f3 {
  strings:
    $key_b6f3 = { e2 9b [2] 96 83 [2] d1 81 [2] 96 90 [2] d8 9c [2] d4 96 [2] c3 9d [2] d8 d3 [2] e5 }

  condition:
    any of them
}