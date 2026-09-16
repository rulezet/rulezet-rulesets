rule TTP_XOR_MULT_DOSStub_11e2 {
  strings:
    $key_11e2 = { 45 8a [2] 31 92 [2] 76 90 [2] 31 81 [2] 7f 8d [2] 73 87 [2] 64 8c [2] 7f c2 [2] 42 }

  condition:
    any of them
}