rule TTP_XOR_MULT_DOSStub_7f27 {
  strings:
    $key_7f27 = { 2b 4f [2] 5f 57 [2] 18 55 [2] 5f 44 [2] 11 48 [2] 1d 42 [2] 0a 49 [2] 11 07 [2] 2c }

  condition:
    any of them
}