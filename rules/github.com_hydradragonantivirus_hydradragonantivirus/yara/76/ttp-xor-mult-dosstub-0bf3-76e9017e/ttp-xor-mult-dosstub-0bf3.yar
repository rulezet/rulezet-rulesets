rule TTP_XOR_MULT_DOSStub_0bf3 {
  strings:
    $key_0bf3 = { 5f 9b [2] 2b 83 [2] 6c 81 [2] 2b 90 [2] 65 9c [2] 69 96 [2] 7e 9d [2] 65 d3 [2] 58 }

  condition:
    any of them
}