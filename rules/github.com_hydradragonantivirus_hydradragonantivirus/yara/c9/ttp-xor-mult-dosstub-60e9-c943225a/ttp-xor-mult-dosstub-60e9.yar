rule TTP_XOR_MULT_DOSStub_60e9 {
  strings:
    $key_60e9 = { 34 81 [2] 40 99 [2] 07 9b [2] 40 8a [2] 0e 86 [2] 02 8c [2] 15 87 [2] 0e c9 [2] 33 }

  condition:
    any of them
}