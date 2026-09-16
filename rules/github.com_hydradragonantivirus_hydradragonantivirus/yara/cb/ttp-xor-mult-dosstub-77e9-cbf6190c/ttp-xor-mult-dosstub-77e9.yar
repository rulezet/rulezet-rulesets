rule TTP_XOR_MULT_DOSStub_77e9 {
  strings:
    $key_77e9 = { 23 81 [2] 57 99 [2] 10 9b [2] 57 8a [2] 19 86 [2] 15 8c [2] 02 87 [2] 19 c9 [2] 24 }

  condition:
    any of them
}