rule TTP_XOR_MULT_DOSStub_13e2 {
  strings:
    $key_13e2 = { 47 8a [2] 33 92 [2] 74 90 [2] 33 81 [2] 7d 8d [2] 71 87 [2] 66 8c [2] 7d c2 [2] 40 }

  condition:
    any of them
}