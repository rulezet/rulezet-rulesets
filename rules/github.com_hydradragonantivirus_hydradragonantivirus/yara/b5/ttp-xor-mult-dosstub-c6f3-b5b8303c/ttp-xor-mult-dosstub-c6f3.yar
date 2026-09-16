rule TTP_XOR_MULT_DOSStub_c6f3 {
  strings:
    $key_c6f3 = { 92 9b [2] e6 83 [2] a1 81 [2] e6 90 [2] a8 9c [2] a4 96 [2] b3 9d [2] a8 d3 [2] 95 }

  condition:
    any of them
}