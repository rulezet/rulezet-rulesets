rule TTP_XOR_MULT_DOSStub_37e9 {
  strings:
    $key_37e9 = { 63 81 [2] 17 99 [2] 50 9b [2] 17 8a [2] 59 86 [2] 55 8c [2] 42 87 [2] 59 c9 [2] 64 }

  condition:
    any of them
}