rule TTP_XOR_MULT_DOSStub_4f62 {
  strings:
    $key_4f62 = { 1b 0a [2] 6f 12 [2] 28 10 [2] 6f 01 [2] 21 0d [2] 2d 07 [2] 3a 0c [2] 21 42 [2] 1c }

  condition:
    any of them
}