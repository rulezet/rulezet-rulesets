rule TTP_XOR_MULT_DOSStub_29ac {
  strings:
    $key_29ac = { 7d c4 [2] 09 dc [2] 4e de [2] 09 cf [2] 47 c3 [2] 4b c9 [2] 5c c2 [2] 47 8c [2] 7a }

  condition:
    any of them
}