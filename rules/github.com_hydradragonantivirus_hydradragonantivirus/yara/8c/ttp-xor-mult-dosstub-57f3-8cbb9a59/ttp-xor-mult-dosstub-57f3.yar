rule TTP_XOR_MULT_DOSStub_57f3 {
  strings:
    $key_57f3 = { 03 9b [2] 77 83 [2] 30 81 [2] 77 90 [2] 39 9c [2] 35 96 [2] 22 9d [2] 39 d3 [2] 04 }

  condition:
    any of them
}