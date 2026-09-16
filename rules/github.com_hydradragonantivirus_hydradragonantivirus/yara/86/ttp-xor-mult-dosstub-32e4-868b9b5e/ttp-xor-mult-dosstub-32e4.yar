rule TTP_XOR_MULT_DOSStub_32e4 {
  strings:
    $key_32e4 = { 66 8c [2] 12 94 [2] 55 96 [2] 12 87 [2] 5c 8b [2] 50 81 [2] 47 8a [2] 5c c4 [2] 61 }

  condition:
    any of them
}