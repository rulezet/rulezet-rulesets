rule TTP_XOR_MULT_DOSStub_79f3 {
  strings:
    $key_79f3 = { 2d 9b [2] 59 83 [2] 1e 81 [2] 59 90 [2] 17 9c [2] 1b 96 [2] 0c 9d [2] 17 d3 [2] 2a }

  condition:
    any of them
}