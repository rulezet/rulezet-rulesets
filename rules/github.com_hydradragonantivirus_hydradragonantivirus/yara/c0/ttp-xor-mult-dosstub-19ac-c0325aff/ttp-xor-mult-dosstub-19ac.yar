rule TTP_XOR_MULT_DOSStub_19ac {
  strings:
    $key_19ac = { 4d c4 [2] 39 dc [2] 7e de [2] 39 cf [2] 77 c3 [2] 7b c9 [2] 6c c2 [2] 77 8c [2] 4a }

  condition:
    any of them
}