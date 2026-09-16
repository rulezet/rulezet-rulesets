rule TTP_XOR_MULT_DOSStub_77f3 {
  strings:
    $key_77f3 = { 23 9b [2] 57 83 [2] 10 81 [2] 57 90 [2] 19 9c [2] 15 96 [2] 02 9d [2] 19 d3 [2] 24 }

  condition:
    any of them
}