rule TTP_XOR_MULT_DOSStub_5917 {
  strings:
    $key_5917 = { 0d 7f [2] 79 67 [2] 3e 65 [2] 79 74 [2] 37 78 [2] 3b 72 [2] 2c 79 [2] 37 37 [2] 0a }

  condition:
    any of them
}