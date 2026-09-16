rule TTP_XOR_MULT_DOSStub_35e9 {
  strings:
    $key_35e9 = { 61 81 [2] 15 99 [2] 52 9b [2] 15 8a [2] 5b 86 [2] 57 8c [2] 40 87 [2] 5b c9 [2] 66 }

  condition:
    any of them
}