rule TTP_XOR_MULT_DOSStub_4bf3 {
  strings:
    $key_4bf3 = { 1f 9b [2] 6b 83 [2] 2c 81 [2] 6b 90 [2] 25 9c [2] 29 96 [2] 3e 9d [2] 25 d3 [2] 18 }

  condition:
    any of them
}