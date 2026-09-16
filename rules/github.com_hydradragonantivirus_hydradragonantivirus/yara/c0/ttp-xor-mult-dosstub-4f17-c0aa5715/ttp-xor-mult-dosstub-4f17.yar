rule TTP_XOR_MULT_DOSStub_4f17 {
  strings:
    $key_4f17 = { 1b 7f [2] 6f 67 [2] 28 65 [2] 6f 74 [2] 21 78 [2] 2d 72 [2] 3a 79 [2] 21 37 [2] 1c }

  condition:
    any of them
}