rule TTP_XOR_MULT_DOSStub_1bf3 {
  strings:
    $key_1bf3 = { 4f 9b [2] 3b 83 [2] 7c 81 [2] 3b 90 [2] 75 9c [2] 79 96 [2] 6e 9d [2] 75 d3 [2] 48 }

  condition:
    any of them
}