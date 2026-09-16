rule TTP_XOR_MULT_DOSStub_5927 {
  strings:
    $key_5927 = { 0d 4f [2] 79 57 [2] 3e 55 [2] 79 44 [2] 37 48 [2] 3b 42 [2] 2c 49 [2] 37 07 [2] 0a }

  condition:
    any of them
}