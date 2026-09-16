rule TTP_XOR_MULT_DOSStub_79e4 {
  strings:
    $key_79e4 = { 2d 8c [2] 59 94 [2] 1e 96 [2] 59 87 [2] 17 8b [2] 1b 81 [2] 0c 8a [2] 17 c4 [2] 2a }

  condition:
    any of them
}