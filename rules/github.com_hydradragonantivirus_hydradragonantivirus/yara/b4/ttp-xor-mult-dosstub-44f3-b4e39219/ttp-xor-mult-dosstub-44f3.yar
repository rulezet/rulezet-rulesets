rule TTP_XOR_MULT_DOSStub_44f3 {
  strings:
    $key_44f3 = { 10 9b [2] 64 83 [2] 23 81 [2] 64 90 [2] 2a 9c [2] 26 96 [2] 31 9d [2] 2a d3 [2] 17 }

  condition:
    any of them
}