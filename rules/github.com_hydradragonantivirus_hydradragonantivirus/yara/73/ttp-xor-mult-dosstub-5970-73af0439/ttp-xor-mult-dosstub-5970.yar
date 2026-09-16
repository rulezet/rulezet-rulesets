rule TTP_XOR_MULT_DOSStub_5970 {
  strings:
    $key_5970 = { 0d 18 [2] 79 00 [2] 3e 02 [2] 79 13 [2] 37 1f [2] 3b 15 [2] 2c 1e [2] 37 50 [2] 0a }

  condition:
    any of them
}