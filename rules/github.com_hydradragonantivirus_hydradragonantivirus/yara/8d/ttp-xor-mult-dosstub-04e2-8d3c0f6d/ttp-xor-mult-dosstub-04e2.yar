rule TTP_XOR_MULT_DOSStub_04e2 {
  strings:
    $key_04e2 = { 50 8a [2] 24 92 [2] 63 90 [2] 24 81 [2] 6a 8d [2] 66 87 [2] 71 8c [2] 6a c2 [2] 57 }

  condition:
    any of them
}