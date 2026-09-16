rule TTP_XOR_MULT_DOSStub_07e9 {
  strings:
    $key_07e9 = { 53 81 [2] 27 99 [2] 60 9b [2] 27 8a [2] 69 86 [2] 65 8c [2] 72 87 [2] 69 c9 [2] 54 }

  condition:
    any of them
}