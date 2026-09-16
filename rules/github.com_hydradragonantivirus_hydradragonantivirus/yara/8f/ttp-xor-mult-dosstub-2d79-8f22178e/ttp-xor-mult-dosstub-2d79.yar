rule TTP_XOR_MULT_DOSStub_2d79 {
  strings:
    $key_2d79 = { 79 11 [2] 0d 09 [2] 4a 0b [2] 0d 1a [2] 43 16 [2] 4f 1c [2] 58 17 [2] 43 59 [2] 7e }

  condition:
    any of them
}