rule TTP_XOR_MULT_DOSStub_5de4 {
  strings:
    $key_5de4 = { 09 8c [2] 7d 94 [2] 3a 96 [2] 7d 87 [2] 33 8b [2] 3f 81 [2] 28 8a [2] 33 c4 [2] 0e }

  condition:
    any of them
}