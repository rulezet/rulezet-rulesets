rule TTP_XOR_MULT_DOSStub_0cf3 {
  strings:
    $key_0cf3 = { 58 9b [2] 2c 83 [2] 6b 81 [2] 2c 90 [2] 62 9c [2] 6e 96 [2] 79 9d [2] 62 d3 [2] 5f }

  condition:
    any of them
}