rule TTP_XOR_MULT_DOSStub_2c17 {
  strings:
    $key_2c17 = { 78 7f [2] 0c 67 [2] 4b 65 [2] 0c 74 [2] 42 78 [2] 4e 72 [2] 59 79 [2] 42 37 [2] 7f }

  condition:
    any of them
}