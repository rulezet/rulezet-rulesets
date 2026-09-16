rule TTP_XOR_MULT_DOSStub_4f08 {
  strings:
    $key_4f08 = { 1b 60 [2] 6f 78 [2] 28 7a [2] 6f 6b [2] 21 67 [2] 2d 6d [2] 3a 66 [2] 21 28 [2] 1c }

  condition:
    any of them
}