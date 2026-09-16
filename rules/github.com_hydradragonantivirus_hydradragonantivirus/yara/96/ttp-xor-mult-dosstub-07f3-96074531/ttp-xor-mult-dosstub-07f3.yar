rule TTP_XOR_MULT_DOSStub_07f3 {
  strings:
    $key_07f3 = { 53 9b [2] 27 83 [2] 60 81 [2] 27 90 [2] 69 9c [2] 65 96 [2] 72 9d [2] 69 d3 [2] 54 }

  condition:
    any of them
}