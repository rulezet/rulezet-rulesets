rule TTP_XOR_MULT_DOSStub_5938 {
  strings:
    $key_5938 = { 0d 50 [2] 79 48 [2] 3e 4a [2] 79 5b [2] 37 57 [2] 3b 5d [2] 2c 56 [2] 37 18 [2] 0a }

  condition:
    any of them
}