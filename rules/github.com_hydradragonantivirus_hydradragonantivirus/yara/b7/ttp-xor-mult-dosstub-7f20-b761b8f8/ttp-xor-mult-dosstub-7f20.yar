rule TTP_XOR_MULT_DOSStub_7f20 {
  strings:
    $key_7f20 = { 2b 48 [2] 5f 50 [2] 18 52 [2] 5f 43 [2] 11 4f [2] 1d 45 [2] 0a 4e [2] 11 00 [2] 2c }

  condition:
    any of them
}