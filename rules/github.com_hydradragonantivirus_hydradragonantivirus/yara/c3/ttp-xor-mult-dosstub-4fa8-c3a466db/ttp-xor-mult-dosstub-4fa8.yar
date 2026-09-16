rule TTP_XOR_MULT_DOSStub_4fa8 {
  strings:
    $key_4fa8 = { 1b c0 [2] 6f d8 [2] 28 da [2] 6f cb [2] 21 c7 [2] 2d cd [2] 3a c6 [2] 21 88 [2] 1c }

  condition:
    any of them
}