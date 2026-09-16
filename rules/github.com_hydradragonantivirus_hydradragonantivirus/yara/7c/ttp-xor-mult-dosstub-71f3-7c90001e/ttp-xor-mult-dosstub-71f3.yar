rule TTP_XOR_MULT_DOSStub_71f3 {
  strings:
    $key_71f3 = { 25 9b [2] 51 83 [2] 16 81 [2] 51 90 [2] 1f 9c [2] 13 96 [2] 04 9d [2] 1f d3 [2] 22 }

  condition:
    any of them
}