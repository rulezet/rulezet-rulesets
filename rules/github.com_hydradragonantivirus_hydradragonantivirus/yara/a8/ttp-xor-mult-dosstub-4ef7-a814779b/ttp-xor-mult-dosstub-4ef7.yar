rule TTP_XOR_MULT_DOSStub_4ef7 {
  strings:
    $key_4ef7 = { 1a 9f [2] 6e 87 [2] 29 85 [2] 6e 94 [2] 20 98 [2] 2c 92 [2] 3b 99 [2] 20 d7 [2] 1d }

  condition:
    any of them
}