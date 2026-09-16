rule TTP_XOR_MULT_DOSStub_2d5c {
  strings:
    $key_2d5c = { 79 34 [2] 0d 2c [2] 4a 2e [2] 0d 3f [2] 43 33 [2] 4f 39 [2] 58 32 [2] 43 7c [2] 7e }

  condition:
    any of them
}