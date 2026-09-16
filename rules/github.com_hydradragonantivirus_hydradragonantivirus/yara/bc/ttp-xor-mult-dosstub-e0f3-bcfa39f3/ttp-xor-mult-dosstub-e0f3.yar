rule TTP_XOR_MULT_DOSStub_e0f3 {
  strings:
    $key_e0f3 = { b4 9b [2] c0 83 [2] 87 81 [2] c0 90 [2] 8e 9c [2] 82 96 [2] 95 9d [2] 8e d3 [2] b3 }

  condition:
    any of them
}