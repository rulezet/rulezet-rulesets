rule TTP_XOR_MULT_DOSStub_37e4 {
  strings:
    $key_37e4 = { 63 8c [2] 17 94 [2] 50 96 [2] 17 87 [2] 59 8b [2] 55 81 [2] 42 8a [2] 59 c4 [2] 64 }

  condition:
    any of them
}