rule TTP_XOR_MULT_DOSStub_e2f3 {
  strings:
    $key_e2f3 = { b6 9b [2] c2 83 [2] 85 81 [2] c2 90 [2] 8c 9c [2] 80 96 [2] 97 9d [2] 8c d3 [2] b1 }

  condition:
    any of them
}