rule TTP_XOR_MULT_DOSStub_7f56 {
  strings:
    $key_7f56 = { 2b 3e [2] 5f 26 [2] 18 24 [2] 5f 35 [2] 11 39 [2] 1d 33 [2] 0a 38 [2] 11 76 [2] 2c }

  condition:
    any of them
}