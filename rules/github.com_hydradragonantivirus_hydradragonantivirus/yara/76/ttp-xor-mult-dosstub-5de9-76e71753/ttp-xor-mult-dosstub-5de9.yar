rule TTP_XOR_MULT_DOSStub_5de9 {
  strings:
    $key_5de9 = { 09 81 [2] 7d 99 [2] 3a 9b [2] 7d 8a [2] 33 86 [2] 3f 8c [2] 28 87 [2] 33 c9 [2] 0e }

  condition:
    any of them
}