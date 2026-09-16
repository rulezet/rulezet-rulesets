rule TTP_XOR_MULT_DOSStub_7f70 {
  strings:
    $key_7f70 = { 2b 18 [2] 5f 00 [2] 18 02 [2] 5f 13 [2] 11 1f [2] 1d 15 [2] 0a 1e [2] 11 50 [2] 2c }

  condition:
    any of them
}