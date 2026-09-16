rule TTP_XOR_MULT_DOSStub_4a07 {
  strings:
    $key_4a07 = { 1e 6f [2] 6a 77 [2] 2d 75 [2] 6a 64 [2] 24 68 [2] 28 62 [2] 3f 69 [2] 24 27 [2] 19 }

  condition:
    any of them
}