rule TTP_XOR_MULT_DOSStub_7f47 {
  strings:
    $key_7f47 = { 2b 2f [2] 5f 37 [2] 18 35 [2] 5f 24 [2] 11 28 [2] 1d 22 [2] 0a 29 [2] 11 67 [2] 2c }

  condition:
    any of them
}