rule TTP_XOR_MULT_DOSStub_41e2 {
  strings:
    $key_41e2 = { 15 8a [2] 61 92 [2] 26 90 [2] 61 81 [2] 2f 8d [2] 23 87 [2] 34 8c [2] 2f c2 [2] 12 }

  condition:
    any of them
}