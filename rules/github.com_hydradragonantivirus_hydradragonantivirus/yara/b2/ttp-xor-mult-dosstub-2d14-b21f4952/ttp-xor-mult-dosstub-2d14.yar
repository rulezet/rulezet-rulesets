rule TTP_XOR_MULT_DOSStub_2d14 {
  strings:
    $key_2d14 = { 79 7c [2] 0d 64 [2] 4a 66 [2] 0d 77 [2] 43 7b [2] 4f 71 [2] 58 7a [2] 43 34 [2] 7e }

  condition:
    any of them
}