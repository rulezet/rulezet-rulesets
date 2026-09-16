rule TTP_XOR_MULT_DOSStub_07e4 {
  strings:
    $key_07e4 = { 53 8c [2] 27 94 [2] 60 96 [2] 27 87 [2] 69 8b [2] 65 81 [2] 72 8a [2] 69 c4 [2] 54 }

  condition:
    any of them
}