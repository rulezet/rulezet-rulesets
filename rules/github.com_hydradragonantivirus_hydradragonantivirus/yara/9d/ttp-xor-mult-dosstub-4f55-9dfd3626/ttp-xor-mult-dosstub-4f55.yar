rule TTP_XOR_MULT_DOSStub_4f55 {
  strings:
    $key_4f55 = { 1b 3d [2] 6f 25 [2] 28 27 [2] 6f 36 [2] 21 3a [2] 2d 30 [2] 3a 3b [2] 21 75 [2] 1c }

  condition:
    any of them
}