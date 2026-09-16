rule TTP_XOR_MULT_DOSStub_2d19 {
  strings:
    $key_2d19 = { 79 71 [2] 0d 69 [2] 4a 6b [2] 0d 7a [2] 43 76 [2] 4f 7c [2] 58 77 [2] 43 39 [2] 7e }

  condition:
    any of them
}