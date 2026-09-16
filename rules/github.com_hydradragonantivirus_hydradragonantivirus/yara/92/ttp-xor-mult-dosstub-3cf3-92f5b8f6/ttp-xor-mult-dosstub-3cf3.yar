rule TTP_XOR_MULT_DOSStub_3cf3 {
  strings:
    $key_3cf3 = { 68 9b [2] 1c 83 [2] 5b 81 [2] 1c 90 [2] 52 9c [2] 5e 96 [2] 49 9d [2] 52 d3 [2] 6f }

  condition:
    any of them
}