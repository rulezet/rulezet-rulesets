rule TTP_XOR_MULT_DOSStub_7bf3 {
  strings:
    $key_7bf3 = { 2f 9b [2] 5b 83 [2] 1c 81 [2] 5b 90 [2] 15 9c [2] 19 96 [2] 0e 9d [2] 15 d3 [2] 28 }

  condition:
    any of them
}