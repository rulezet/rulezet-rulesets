rule TTP_XOR_MULT_DOSStub_2de9 {
  strings:
    $key_2de9 = { 79 81 [2] 0d 99 [2] 4a 9b [2] 0d 8a [2] 43 86 [2] 4f 8c [2] 58 87 [2] 43 c9 [2] 7e }

  condition:
    any of them
}