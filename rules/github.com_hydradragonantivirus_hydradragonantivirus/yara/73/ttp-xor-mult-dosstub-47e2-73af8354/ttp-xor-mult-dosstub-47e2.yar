rule TTP_XOR_MULT_DOSStub_47e2 {
  strings:
    $key_47e2 = { 13 8a [2] 67 92 [2] 20 90 [2] 67 81 [2] 29 8d [2] 25 87 [2] 32 8c [2] 29 c2 [2] 14 }

  condition:
    any of them
}