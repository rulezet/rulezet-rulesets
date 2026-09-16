rule TTP_XOR_MULT_DOSStub_2d08 {
  strings:
    $key_2d08 = { 79 60 [2] 0d 78 [2] 4a 7a [2] 0d 6b [2] 43 67 [2] 4f 6d [2] 58 66 [2] 43 28 [2] 7e }

  condition:
    any of them
}