rule TTP_XOR_MULT_DOSStub_2d25 {
  strings:
    $key_2d25 = { 79 4d [2] 0d 55 [2] 4a 57 [2] 0d 46 [2] 43 4a [2] 4f 40 [2] 58 4b [2] 43 05 [2] 7e }

  condition:
    any of them
}