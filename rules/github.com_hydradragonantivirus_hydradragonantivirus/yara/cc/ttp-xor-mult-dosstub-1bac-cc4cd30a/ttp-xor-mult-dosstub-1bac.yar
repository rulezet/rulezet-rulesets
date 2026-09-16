rule TTP_XOR_MULT_DOSStub_1bac {
  strings:
    $key_1bac = { 4f c4 [2] 3b dc [2] 7c de [2] 3b cf [2] 75 c3 [2] 79 c9 [2] 6e c2 [2] 75 8c [2] 48 }

  condition:
    any of them
}