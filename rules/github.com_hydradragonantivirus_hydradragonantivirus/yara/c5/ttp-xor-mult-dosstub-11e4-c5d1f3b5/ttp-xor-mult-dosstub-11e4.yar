rule TTP_XOR_MULT_DOSStub_11e4 {
  strings:
    $key_11e4 = { 45 8c [2] 31 94 [2] 76 96 [2] 31 87 [2] 7f 8b [2] 73 81 [2] 64 8a [2] 7f c4 [2] 42 }

  condition:
    any of them
}