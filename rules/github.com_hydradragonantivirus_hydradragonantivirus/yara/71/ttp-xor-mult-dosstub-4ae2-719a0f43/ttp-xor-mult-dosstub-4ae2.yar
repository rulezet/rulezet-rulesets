rule TTP_XOR_MULT_DOSStub_4ae2 {
  strings:
    $key_4ae2 = { 1e 8a [2] 6a 92 [2] 2d 90 [2] 6a 81 [2] 24 8d [2] 28 87 [2] 3f 8c [2] 24 c2 [2] 19 }

  condition:
    any of them
}