rule TTP_XOR_MULT_DOSStub_30e9 {
  strings:
    $key_30e9 = { 64 81 [2] 10 99 [2] 57 9b [2] 10 8a [2] 5e 86 [2] 52 8c [2] 45 87 [2] 5e c9 [2] 63 }

  condition:
    any of them
}