rule TTP_XOR_MULT_DOSStub_04e9 {
  strings:
    $key_04e9 = { 50 81 [2] 24 99 [2] 63 9b [2] 24 8a [2] 6a 86 [2] 66 8c [2] 71 87 [2] 6a c9 [2] 57 }

  condition:
    any of them
}