rule TTP_XOR_MULT_DOSStub_2de2 {
  strings:
    $key_2de2 = { 79 8a [2] 0d 92 [2] 4a 90 [2] 0d 81 [2] 43 8d [2] 4f 87 [2] 58 8c [2] 43 c2 [2] 7e }

  condition:
    any of them
}