rule TTP_XOR_MULT_DOSStub_5921 {
  strings:
    $key_5921 = { 0d 49 [2] 79 51 [2] 3e 53 [2] 79 42 [2] 37 4e [2] 3b 44 [2] 2c 4f [2] 37 01 [2] 0a }

  condition:
    any of them
}