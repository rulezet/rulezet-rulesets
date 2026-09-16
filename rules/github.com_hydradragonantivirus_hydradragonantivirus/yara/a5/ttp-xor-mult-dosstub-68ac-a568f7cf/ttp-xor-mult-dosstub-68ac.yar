rule TTP_XOR_MULT_DOSStub_68ac {
  strings:
    $key_68ac = { 3c c4 [2] 48 dc [2] 0f de [2] 48 cf [2] 06 c3 [2] 0a c9 [2] 1d c2 [2] 06 8c [2] 3b }

  condition:
    any of them
}