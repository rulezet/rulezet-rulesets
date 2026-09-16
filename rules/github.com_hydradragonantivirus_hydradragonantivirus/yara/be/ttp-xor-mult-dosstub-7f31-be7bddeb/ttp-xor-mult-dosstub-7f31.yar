rule TTP_XOR_MULT_DOSStub_7f31 {
  strings:
    $key_7f31 = { 2b 59 [2] 5f 41 [2] 18 43 [2] 5f 52 [2] 11 5e [2] 1d 54 [2] 0a 5f [2] 11 11 [2] 2c }

  condition:
    any of them
}