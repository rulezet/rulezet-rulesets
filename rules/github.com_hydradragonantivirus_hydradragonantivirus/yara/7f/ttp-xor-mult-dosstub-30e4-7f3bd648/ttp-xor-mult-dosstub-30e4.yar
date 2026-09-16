rule TTP_XOR_MULT_DOSStub_30e4 {
  strings:
    $key_30e4 = { 64 8c [2] 10 94 [2] 57 96 [2] 10 87 [2] 5e 8b [2] 52 81 [2] 45 8a [2] 5e c4 [2] 63 }

  condition:
    any of them
}