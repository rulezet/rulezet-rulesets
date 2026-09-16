rule TTP_XOR_MULT_DOSStub_26e9 {
  strings:
    $key_26e9 = { 72 81 [2] 06 99 [2] 41 9b [2] 06 8a [2] 48 86 [2] 44 8c [2] 53 87 [2] 48 c9 [2] 75 }

  condition:
    any of them
}