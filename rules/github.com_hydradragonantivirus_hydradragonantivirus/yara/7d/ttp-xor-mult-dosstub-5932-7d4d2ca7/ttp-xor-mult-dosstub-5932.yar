rule TTP_XOR_MULT_DOSStub_5932 {
  strings:
    $key_5932 = { 0d 5a [2] 79 42 [2] 3e 40 [2] 79 51 [2] 37 5d [2] 3b 57 [2] 2c 5c [2] 37 12 [2] 0a }

  condition:
    any of them
}