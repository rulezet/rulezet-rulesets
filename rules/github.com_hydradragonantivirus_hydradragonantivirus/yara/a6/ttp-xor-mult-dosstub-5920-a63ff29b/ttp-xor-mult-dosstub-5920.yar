rule TTP_XOR_MULT_DOSStub_5920 {
  strings:
    $key_5920 = { 0d 48 [2] 79 50 [2] 3e 52 [2] 79 43 [2] 37 4f [2] 3b 45 [2] 2c 4e [2] 37 00 [2] 0a }

  condition:
    any of them
}