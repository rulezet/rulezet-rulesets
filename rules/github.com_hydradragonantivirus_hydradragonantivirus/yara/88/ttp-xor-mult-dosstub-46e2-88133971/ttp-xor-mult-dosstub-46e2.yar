rule TTP_XOR_MULT_DOSStub_46e2 {
  strings:
    $key_46e2 = { 12 8a [2] 66 92 [2] 21 90 [2] 66 81 [2] 28 8d [2] 24 87 [2] 33 8c [2] 28 c2 [2] 15 }

  condition:
    any of them
}