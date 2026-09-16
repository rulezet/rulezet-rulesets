rule TTP_XOR_MULT_DOSStub_18e2 {
  strings:
    $key_18e2 = { 4c 8a [2] 38 92 [2] 7f 90 [2] 38 81 [2] 76 8d [2] 7a 87 [2] 6d 8c [2] 76 c2 [2] 4b }

  condition:
    any of them
}