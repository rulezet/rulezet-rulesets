rule TTP_XOR_MULT_DOSStub_4df3 {
  strings:
    $key_4df3 = { 19 9b [2] 6d 83 [2] 2a 81 [2] 6d 90 [2] 23 9c [2] 2f 96 [2] 38 9d [2] 23 d3 [2] 1e }

  condition:
    any of them
}