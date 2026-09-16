rule TTP_XOR_MULT_DOSStub_11f3 {
  strings:
    $key_11f3 = { 45 9b [2] 31 83 [2] 76 81 [2] 31 90 [2] 7f 9c [2] 73 96 [2] 64 9d [2] 7f d3 [2] 42 }

  condition:
    any of them
}