rule TTP_XOR_MULT_DOSStub_2d2c {
  strings:
    $key_2d2c = { 79 44 [2] 0d 5c [2] 4a 5e [2] 0d 4f [2] 43 43 [2] 4f 49 [2] 58 42 [2] 43 0c [2] 7e }

  condition:
    any of them
}