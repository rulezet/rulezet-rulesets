rule TTP_XOR_MULT_DOSStub_2d65 {
  strings:
    $key_2d65 = { 79 0d [2] 0d 15 [2] 4a 17 [2] 0d 06 [2] 43 0a [2] 4f 00 [2] 58 0b [2] 43 45 [2] 7e }

  condition:
    any of them
}