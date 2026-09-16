rule TTP_XOR_MULT_DOSStub_3de4 {
  strings:
    $key_3de4 = { 69 8c [2] 1d 94 [2] 5a 96 [2] 1d 87 [2] 53 8b [2] 5f 81 [2] 48 8a [2] 53 c4 [2] 6e }

  condition:
    any of them
}