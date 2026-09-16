rule TTP_XOR_MULT_DOSStub_4f57 {
  strings:
    $key_4f57 = { 1b 3f [2] 6f 27 [2] 28 25 [2] 6f 34 [2] 21 38 [2] 2d 32 [2] 3a 39 [2] 21 77 [2] 1c }

  condition:
    any of them
}