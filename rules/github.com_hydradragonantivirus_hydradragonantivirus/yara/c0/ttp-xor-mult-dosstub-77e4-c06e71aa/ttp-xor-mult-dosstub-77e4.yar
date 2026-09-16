rule TTP_XOR_MULT_DOSStub_77e4 {
  strings:
    $key_77e4 = { 23 8c [2] 57 94 [2] 10 96 [2] 57 87 [2] 19 8b [2] 15 81 [2] 02 8a [2] 19 c4 [2] 24 }

  condition:
    any of them
}