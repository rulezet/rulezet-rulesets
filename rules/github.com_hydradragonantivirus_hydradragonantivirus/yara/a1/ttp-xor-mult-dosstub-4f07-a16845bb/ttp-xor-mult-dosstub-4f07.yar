rule TTP_XOR_MULT_DOSStub_4f07 {
  strings:
    $key_4f07 = { 1b 6f [2] 6f 77 [2] 28 75 [2] 6f 64 [2] 21 68 [2] 2d 62 [2] 3a 69 [2] 21 27 [2] 1c }

  condition:
    any of them
}