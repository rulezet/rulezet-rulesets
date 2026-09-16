rule TTP_XOR_MULT_DOSStub_7f40 {
  strings:
    $key_7f40 = { 2b 28 [2] 5f 30 [2] 18 32 [2] 5f 23 [2] 11 2f [2] 1d 25 [2] 0a 2e [2] 11 60 [2] 2c }

  condition:
    any of them
}