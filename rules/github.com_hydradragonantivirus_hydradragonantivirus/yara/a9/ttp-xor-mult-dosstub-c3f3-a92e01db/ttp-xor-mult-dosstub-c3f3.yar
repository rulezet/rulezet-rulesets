rule TTP_XOR_MULT_DOSStub_c3f3 {
  strings:
    $key_c3f3 = { 97 9b [2] e3 83 [2] a4 81 [2] e3 90 [2] ad 9c [2] a1 96 [2] b6 9d [2] ad d3 [2] 90 }

  condition:
    any of them
}