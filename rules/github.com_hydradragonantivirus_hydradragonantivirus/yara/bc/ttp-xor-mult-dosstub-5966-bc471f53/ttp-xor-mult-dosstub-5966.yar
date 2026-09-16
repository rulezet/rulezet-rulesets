rule TTP_XOR_MULT_DOSStub_5966 {
  strings:
    $key_5966 = { 0d 0e [2] 79 16 [2] 3e 14 [2] 79 05 [2] 37 09 [2] 3b 03 [2] 2c 08 [2] 37 46 [2] 0a }

  condition:
    any of them
}