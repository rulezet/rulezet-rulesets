rule TTP_XOR_MULT_DOSStub_4f59 {
  strings:
    $key_4f59 = { 1b 31 [2] 6f 29 [2] 28 2b [2] 6f 3a [2] 21 36 [2] 2d 3c [2] 3a 37 [2] 21 79 [2] 1c }

  condition:
    any of them
}