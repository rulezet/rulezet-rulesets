rule TTP_XOR_MULT_DOSStub_2cf3 {
  strings:
    $key_2cf3 = { 78 9b [2] 0c 83 [2] 4b 81 [2] 0c 90 [2] 42 9c [2] 4e 96 [2] 59 9d [2] 42 d3 [2] 7f }

  condition:
    any of them
}