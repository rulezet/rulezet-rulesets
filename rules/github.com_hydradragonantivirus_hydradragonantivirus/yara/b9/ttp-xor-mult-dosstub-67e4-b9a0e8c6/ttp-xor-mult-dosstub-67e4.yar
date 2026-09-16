rule TTP_XOR_MULT_DOSStub_67e4 {
  strings:
    $key_67e4 = { 33 8c [2] 47 94 [2] 00 96 [2] 47 87 [2] 09 8b [2] 05 81 [2] 12 8a [2] 09 c4 [2] 34 }

  condition:
    any of them
}