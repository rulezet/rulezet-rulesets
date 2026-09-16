rule TTP_XOR_MULT_DOSStub_17e4 {
  strings:
    $key_17e4 = { 43 8c [2] 37 94 [2] 70 96 [2] 37 87 [2] 79 8b [2] 75 81 [2] 62 8a [2] 79 c4 [2] 44 }

  condition:
    any of them
}