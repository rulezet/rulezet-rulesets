rule TTP_XOR_MULT_DOSStub_4f15 {
  strings:
    $key_4f15 = { 1b 7d [2] 6f 65 [2] 28 67 [2] 6f 76 [2] 21 7a [2] 2d 70 [2] 3a 7b [2] 21 35 [2] 1c }

  condition:
    any of them
}