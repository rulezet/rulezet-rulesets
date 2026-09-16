rule TTP_XOR_MULT_DOSStub_7f07 {
  strings:
    $key_7f07 = { 2b 6f [2] 5f 77 [2] 18 75 [2] 5f 64 [2] 11 68 [2] 1d 62 [2] 0a 69 [2] 11 27 [2] 2c }

  condition:
    any of them
}