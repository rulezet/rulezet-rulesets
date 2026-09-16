rule TTP_XOR_MULT_DOSStub_01ef {
  strings:
    $key_01ef = { 55 87 [2] 21 9f [2] 66 9d [2] 21 8c [2] 6f 80 [2] 63 8a [2] 74 81 [2] 6f cf [2] 52 }

  condition:
    any of them
}