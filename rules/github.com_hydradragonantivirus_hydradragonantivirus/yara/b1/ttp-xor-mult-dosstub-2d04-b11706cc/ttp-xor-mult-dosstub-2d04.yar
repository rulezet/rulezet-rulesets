rule TTP_XOR_MULT_DOSStub_2d04 {
  strings:
    $key_2d04 = { 79 6c [2] 0d 74 [2] 4a 76 [2] 0d 67 [2] 43 6b [2] 4f 61 [2] 58 6a [2] 43 24 [2] 7e }

  condition:
    any of them
}