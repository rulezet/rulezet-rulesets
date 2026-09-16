rule TTP_XOR_MULT_DOSStub_3a07 {
  strings:
    $key_3a07 = { 6e 6f [2] 1a 77 [2] 5d 75 [2] 1a 64 [2] 54 68 [2] 58 62 [2] 4f 69 [2] 54 27 [2] 69 }

  condition:
    any of them
}