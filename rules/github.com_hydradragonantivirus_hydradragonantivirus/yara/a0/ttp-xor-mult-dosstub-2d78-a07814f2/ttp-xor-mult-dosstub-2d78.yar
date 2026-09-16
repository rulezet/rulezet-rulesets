rule TTP_XOR_MULT_DOSStub_2d78 {
  strings:
    $key_2d78 = { 79 10 [2] 0d 08 [2] 4a 0a [2] 0d 1b [2] 43 17 [2] 4f 1d [2] 58 16 [2] 43 58 [2] 7e }

  condition:
    any of them
}