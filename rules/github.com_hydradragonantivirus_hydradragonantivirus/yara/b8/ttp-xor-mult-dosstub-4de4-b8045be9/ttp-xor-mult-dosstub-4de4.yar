rule TTP_XOR_MULT_DOSStub_4de4 {
  strings:
    $key_4de4 = { 19 8c [2] 6d 94 [2] 2a 96 [2] 6d 87 [2] 23 8b [2] 2f 81 [2] 38 8a [2] 23 c4 [2] 1e }

  condition:
    any of them
}