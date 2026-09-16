rule TTP_XOR_MULT_DOSStub_7de4 {
  strings:
    $key_7de4 = { 29 8c [2] 5d 94 [2] 1a 96 [2] 5d 87 [2] 13 8b [2] 1f 81 [2] 08 8a [2] 13 c4 [2] 2e }

  condition:
    any of them
}