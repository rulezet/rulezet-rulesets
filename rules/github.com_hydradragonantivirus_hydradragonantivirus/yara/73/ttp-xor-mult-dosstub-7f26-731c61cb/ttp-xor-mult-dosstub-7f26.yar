rule TTP_XOR_MULT_DOSStub_7f26 {
  strings:
    $key_7f26 = { 2b 4e [2] 5f 56 [2] 18 54 [2] 5f 45 [2] 11 49 [2] 1d 43 [2] 0a 48 [2] 11 06 [2] 2c }

  condition:
    any of them
}