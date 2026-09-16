rule TTP_XOR_MULT_DOSStub_7ff7 {
  strings:
    $key_7ff7 = { 2b 9f [2] 5f 87 [2] 18 85 [2] 5f 94 [2] 11 98 [2] 1d 92 [2] 0a 99 [2] 11 d7 [2] 2c }

  condition:
    any of them
}