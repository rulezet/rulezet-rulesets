rule TTP_XOR_MULT_DOSStub_04f3 {
  strings:
    $key_04f3 = { 50 9b [2] 24 83 [2] 63 81 [2] 24 90 [2] 6a 9c [2] 66 96 [2] 71 9d [2] 6a d3 [2] 57 }

  condition:
    any of them
}