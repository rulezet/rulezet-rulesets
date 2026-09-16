rule TTP_XOR_MULT_DOSStub_5bf3 {
  strings:
    $key_5bf3 = { 0f 9b [2] 7b 83 [2] 3c 81 [2] 7b 90 [2] 35 9c [2] 39 96 [2] 2e 9d [2] 35 d3 [2] 08 }

  condition:
    any of them
}