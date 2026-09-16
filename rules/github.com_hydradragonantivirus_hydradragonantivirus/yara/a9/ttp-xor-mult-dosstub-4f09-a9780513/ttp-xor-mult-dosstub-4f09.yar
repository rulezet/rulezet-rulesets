rule TTP_XOR_MULT_DOSStub_4f09 {
  strings:
    $key_4f09 = { 1b 61 [2] 6f 79 [2] 28 7b [2] 6f 6a [2] 21 66 [2] 2d 6c [2] 3a 67 [2] 21 29 [2] 1c }

  condition:
    any of them
}