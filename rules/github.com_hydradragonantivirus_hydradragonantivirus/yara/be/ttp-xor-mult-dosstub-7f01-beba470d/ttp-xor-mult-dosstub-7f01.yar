rule TTP_XOR_MULT_DOSStub_7f01 {
  strings:
    $key_7f01 = { 2b 69 [2] 5f 71 [2] 18 73 [2] 5f 62 [2] 11 6e [2] 1d 64 [2] 0a 6f [2] 11 21 [2] 2c }

  condition:
    any of them
}