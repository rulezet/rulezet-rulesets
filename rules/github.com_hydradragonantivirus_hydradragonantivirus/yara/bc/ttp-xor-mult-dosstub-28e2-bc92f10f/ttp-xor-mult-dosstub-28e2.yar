rule TTP_XOR_MULT_DOSStub_28e2 {
  strings:
    $key_28e2 = { 7c 8a [2] 08 92 [2] 4f 90 [2] 08 81 [2] 46 8d [2] 4a 87 [2] 5d 8c [2] 46 c2 [2] 7b }

  condition:
    any of them
}