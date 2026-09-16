rule TTP_XOR_MULT_DOSStub_41e4 {
  strings:
    $key_41e4 = { 15 8c [2] 61 94 [2] 26 96 [2] 61 87 [2] 2f 8b [2] 23 81 [2] 34 8a [2] 2f c4 [2] 12 }

  condition:
    any of them
}