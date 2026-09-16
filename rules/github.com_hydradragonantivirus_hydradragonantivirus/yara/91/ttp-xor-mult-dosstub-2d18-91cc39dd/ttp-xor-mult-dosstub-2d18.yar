rule TTP_XOR_MULT_DOSStub_2d18 {
  strings:
    $key_2d18 = { 79 70 [2] 0d 68 [2] 4a 6a [2] 0d 7b [2] 43 77 [2] 4f 7d [2] 58 76 [2] 43 38 [2] 7e }

  condition:
    any of them
}