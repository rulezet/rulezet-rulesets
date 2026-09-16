rule TTP_XOR_MULT_DOSStub_67e2 {
  strings:
    $key_67e2 = { 33 8a [2] 47 92 [2] 00 90 [2] 47 81 [2] 09 8d [2] 05 87 [2] 12 8c [2] 09 c2 [2] 34 }

  condition:
    any of them
}