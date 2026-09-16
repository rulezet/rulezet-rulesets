rule TTP_XOR_MULT_DOSStub_4361 {
  strings:
    $key_4361 = { 17 09 [2] 63 11 [2] 24 13 [2] 63 02 [2] 2d 0e [2] 21 04 [2] 36 0f [2] 2d 41 [2] 10 }

  condition:
    any of them
}