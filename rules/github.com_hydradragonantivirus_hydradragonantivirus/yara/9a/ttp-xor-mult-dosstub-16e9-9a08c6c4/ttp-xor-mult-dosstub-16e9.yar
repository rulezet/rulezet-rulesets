rule TTP_XOR_MULT_DOSStub_16e9 {
  strings:
    $key_16e9 = { 42 81 [2] 36 99 [2] 71 9b [2] 36 8a [2] 78 86 [2] 74 8c [2] 63 87 [2] 78 c9 [2] 45 }

  condition:
    any of them
}