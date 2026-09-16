rule TTP_XOR_MULT_DOSStub_2de4 {
  strings:
    $key_2de4 = { 79 8c [2] 0d 94 [2] 4a 96 [2] 0d 87 [2] 43 8b [2] 4f 81 [2] 58 8a [2] 43 c4 [2] 7e }

  condition:
    any of them
}