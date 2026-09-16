rule TTP_XOR_MULT_DOSStub_28e9 {
  strings:
    $key_28e9 = { 7c 81 [2] 08 99 [2] 4f 9b [2] 08 8a [2] 46 86 [2] 4a 8c [2] 5d 87 [2] 46 c9 [2] 7b }

  condition:
    any of them
}