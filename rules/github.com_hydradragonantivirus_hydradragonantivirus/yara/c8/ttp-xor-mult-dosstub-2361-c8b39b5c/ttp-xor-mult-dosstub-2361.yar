rule TTP_XOR_MULT_DOSStub_2361 {
  strings:
    $key_2361 = { 77 09 [2] 03 11 [2] 44 13 [2] 03 02 [2] 4d 0e [2] 41 04 [2] 56 0f [2] 4d 41 [2] 70 }

  condition:
    any of them
}