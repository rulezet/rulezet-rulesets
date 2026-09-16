rule TTP_XOR_MULT_DOSStub_02e4 {
  strings:
    $key_02e4 = { 56 8c [2] 22 94 [2] 65 96 [2] 22 87 [2] 6c 8b [2] 60 81 [2] 77 8a [2] 6c c4 [2] 51 }

  condition:
    any of them
}