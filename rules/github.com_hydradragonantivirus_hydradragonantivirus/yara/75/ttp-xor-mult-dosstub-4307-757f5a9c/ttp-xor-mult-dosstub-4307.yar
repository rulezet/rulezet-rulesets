rule TTP_XOR_MULT_DOSStub_4307 {
  strings:
    $key_4307 = { 17 6f [2] 63 77 [2] 24 75 [2] 63 64 [2] 2d 68 [2] 21 62 [2] 36 69 [2] 2d 27 [2] 10 }

  condition:
    any of them
}