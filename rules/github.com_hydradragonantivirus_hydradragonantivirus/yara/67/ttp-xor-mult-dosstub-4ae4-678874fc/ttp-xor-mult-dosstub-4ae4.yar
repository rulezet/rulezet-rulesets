rule TTP_XOR_MULT_DOSStub_4ae4 {
  strings:
    $key_4ae4 = { 1e 8c [2] 6a 94 [2] 2d 96 [2] 6a 87 [2] 24 8b [2] 28 81 [2] 3f 8a [2] 24 c4 [2] 19 }

  condition:
    any of them
}