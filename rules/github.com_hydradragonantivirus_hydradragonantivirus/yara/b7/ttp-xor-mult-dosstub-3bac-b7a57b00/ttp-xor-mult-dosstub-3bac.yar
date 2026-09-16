rule TTP_XOR_MULT_DOSStub_3bac {
  strings:
    $key_3bac = { 6f c4 [2] 1b dc [2] 5c de [2] 1b cf [2] 55 c3 [2] 59 c9 [2] 4e c2 [2] 55 8c [2] 68 }

  condition:
    any of them
}