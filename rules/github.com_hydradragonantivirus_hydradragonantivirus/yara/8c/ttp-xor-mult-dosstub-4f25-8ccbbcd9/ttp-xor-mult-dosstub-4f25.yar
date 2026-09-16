rule TTP_XOR_MULT_DOSStub_4f25 {
  strings:
    $key_4f25 = { 1b 4d [2] 6f 55 [2] 28 57 [2] 6f 46 [2] 21 4a [2] 2d 40 [2] 3a 4b [2] 21 05 [2] 1c }

  condition:
    any of them
}