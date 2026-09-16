rule TTP_XOR_MULT_DOSStub_b2f3 {
  strings:
    $key_b2f3 = { e6 9b [2] 92 83 [2] d5 81 [2] 92 90 [2] dc 9c [2] d0 96 [2] c7 9d [2] dc d3 [2] e1 }

  condition:
    any of them
}