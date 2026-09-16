rule TTP_XOR_MULT_DOSStub_4b70 {
  strings:
    $key_4b70 = { 1f 18 [2] 6b 00 [2] 2c 02 [2] 6b 13 [2] 25 1f [2] 29 15 [2] 3e 1e [2] 25 50 [2] 18 }

  condition:
    any of them
}