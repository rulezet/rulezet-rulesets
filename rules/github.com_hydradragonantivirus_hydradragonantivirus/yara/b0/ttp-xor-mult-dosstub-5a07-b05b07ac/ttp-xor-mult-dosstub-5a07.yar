rule TTP_XOR_MULT_DOSStub_5a07 {
  strings:
    $key_5a07 = { 0e 6f [2] 7a 77 [2] 3d 75 [2] 7a 64 [2] 34 68 [2] 38 62 [2] 2f 69 [2] 34 27 [2] 09 }

  condition:
    any of them
}