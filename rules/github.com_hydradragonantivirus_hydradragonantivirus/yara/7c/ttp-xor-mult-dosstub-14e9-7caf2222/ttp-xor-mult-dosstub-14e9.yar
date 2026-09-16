rule TTP_XOR_MULT_DOSStub_14e9 {
  strings:
    $key_14e9 = { 40 81 [2] 34 99 [2] 73 9b [2] 34 8a [2] 7a 86 [2] 76 8c [2] 61 87 [2] 7a c9 [2] 47 }

  condition:
    any of them
}