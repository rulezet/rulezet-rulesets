rule TTP_XOR_MULT_DOSStub_36ef {
  strings:
    $key_36ef = { 62 87 [2] 16 9f [2] 51 9d [2] 16 8c [2] 58 80 [2] 54 8a [2] 43 81 [2] 58 cf [2] 65 }

  condition:
    any of them
}