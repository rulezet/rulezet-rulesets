rule TTP_XOR_MULT_DOSStub_52f3 {
  strings:
    $key_52f3 = { 06 9b [2] 72 83 [2] 35 81 [2] 72 90 [2] 3c 9c [2] 30 96 [2] 27 9d [2] 3c d3 [2] 01 }

  condition:
    any of them
}