rule TTP_XOR_MULT_DOSStub_2d05 {
  strings:
    $key_2d05 = { 79 6d [2] 0d 75 [2] 4a 77 [2] 0d 66 [2] 43 6a [2] 4f 60 [2] 58 6b [2] 43 25 [2] 7e }

  condition:
    any of them
}