rule TTP_XOR_MULT_DOSStub_76ef {
  strings:
    $key_76ef = { 22 87 [2] 56 9f [2] 11 9d [2] 56 8c [2] 18 80 [2] 14 8a [2] 03 81 [2] 18 cf [2] 25 }

  condition:
    any of them
}