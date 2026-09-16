rule TTP_XOR_MULT_DOSStub_5951 {
  strings:
    $key_5951 = { 0d 39 [2] 79 21 [2] 3e 23 [2] 79 32 [2] 37 3e [2] 3b 34 [2] 2c 3f [2] 37 71 [2] 0a }

  condition:
    any of them
}