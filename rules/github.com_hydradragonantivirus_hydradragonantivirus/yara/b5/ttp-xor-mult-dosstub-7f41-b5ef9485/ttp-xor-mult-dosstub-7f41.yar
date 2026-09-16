rule TTP_XOR_MULT_DOSStub_7f41 {
  strings:
    $key_7f41 = { 2b 29 [2] 5f 31 [2] 18 33 [2] 5f 22 [2] 11 2e [2] 1d 24 [2] 0a 2f [2] 11 61 [2] 2c }

  condition:
    any of them
}