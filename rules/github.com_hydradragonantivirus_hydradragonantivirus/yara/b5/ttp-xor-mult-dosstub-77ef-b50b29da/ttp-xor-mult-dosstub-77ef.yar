rule TTP_XOR_MULT_DOSStub_77ef {
  strings:
    $key_77ef = { 23 87 [2] 57 9f [2] 10 9d [2] 57 8c [2] 19 80 [2] 15 8a [2] 02 81 [2] 19 cf [2] 24 }

  condition:
    any of them
}