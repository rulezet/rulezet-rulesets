rule TTP_XOR_MULT_DOSStub_76f3 {
  strings:
    $key_76f3 = { 22 9b [2] 56 83 [2] 11 81 [2] 56 90 [2] 18 9c [2] 14 96 [2] 03 9d [2] 18 d3 [2] 25 }

  condition:
    any of them
}