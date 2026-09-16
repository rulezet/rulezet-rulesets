rule TTP_XOR_MULT_DOSStub_7ff1 {
  strings:
    $key_7ff1 = { 2b 99 [2] 5f 81 [2] 18 83 [2] 5f 92 [2] 11 9e [2] 1d 94 [2] 0a 9f [2] 11 d1 [2] 2c }

  condition:
    any of them
}