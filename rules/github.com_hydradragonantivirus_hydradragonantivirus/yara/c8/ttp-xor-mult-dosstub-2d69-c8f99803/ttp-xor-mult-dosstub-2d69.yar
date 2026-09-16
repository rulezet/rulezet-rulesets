rule TTP_XOR_MULT_DOSStub_2d69 {
  strings:
    $key_2d69 = { 79 01 [2] 0d 19 [2] 4a 1b [2] 0d 0a [2] 43 06 [2] 4f 0c [2] 58 07 [2] 43 49 [2] 7e }

  condition:
    any of them
}