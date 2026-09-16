rule TTP_XOR_MULT_DOSStub_5941 {
  strings:
    $key_5941 = { 0d 29 [2] 79 31 [2] 3e 33 [2] 79 22 [2] 37 2e [2] 3b 24 [2] 2c 2f [2] 37 61 [2] 0a }

  condition:
    any of them
}