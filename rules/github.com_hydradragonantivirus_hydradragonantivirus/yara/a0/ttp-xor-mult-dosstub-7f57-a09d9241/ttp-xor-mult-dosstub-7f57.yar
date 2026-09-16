rule TTP_XOR_MULT_DOSStub_7f57 {
  strings:
    $key_7f57 = { 2b 3f [2] 5f 27 [2] 18 25 [2] 5f 34 [2] 11 38 [2] 1d 32 [2] 0a 39 [2] 11 77 [2] 2c }

  condition:
    any of them
}