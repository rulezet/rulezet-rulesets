rule TTP_XOR_MULT_DOSStub_67ef {
  strings:
    $key_67ef = { 33 87 [2] 47 9f [2] 00 9d [2] 47 8c [2] 09 80 [2] 05 8a [2] 12 81 [2] 09 cf [2] 34 }

  condition:
    any of them
}