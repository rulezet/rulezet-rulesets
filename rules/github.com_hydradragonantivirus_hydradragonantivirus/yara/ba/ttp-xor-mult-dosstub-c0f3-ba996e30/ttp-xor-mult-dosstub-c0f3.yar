rule TTP_XOR_MULT_DOSStub_c0f3 {
  strings:
    $key_c0f3 = { 94 9b [2] e0 83 [2] a7 81 [2] e0 90 [2] ae 9c [2] a2 96 [2] b5 9d [2] ae d3 [2] 93 }

  condition:
    any of them
}