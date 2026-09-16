rule TTP_XOR_MULT_DOSStub_03e2 {
  strings:
    $key_03e2 = { 57 8a [2] 23 92 [2] 64 90 [2] 23 81 [2] 6d 8d [2] 61 87 [2] 76 8c [2] 6d c2 [2] 50 }

  condition:
    any of them
}