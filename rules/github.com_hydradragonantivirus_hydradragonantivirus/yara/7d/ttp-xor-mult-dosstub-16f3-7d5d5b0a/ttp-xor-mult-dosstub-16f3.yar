rule TTP_XOR_MULT_DOSStub_16f3 {
  strings:
    $key_16f3 = { 42 9b [2] 36 83 [2] 71 81 [2] 36 90 [2] 78 9c [2] 74 96 [2] 63 9d [2] 78 d3 [2] 45 }

  condition:
    any of them
}