rule TTP_XOR_MULT_DOSStub_08ef {
  strings:
    $key_08ef = { 5c 87 [2] 28 9f [2] 6f 9d [2] 28 8c [2] 66 80 [2] 6a 8a [2] 7d 81 [2] 66 cf [2] 5b }

  condition:
    any of them
}