rule TTP_XOR_MULT_DOSStub_4f75 {
  strings:
    $key_4f75 = { 1b 1d [2] 6f 05 [2] 28 07 [2] 6f 16 [2] 21 1a [2] 2d 10 [2] 3a 1b [2] 21 55 [2] 1c }

  condition:
    any of them
}