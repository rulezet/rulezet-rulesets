rule TTP_XOR_MULT_DOSStub_2c47 {
  strings:
    $key_2c47 = { 78 2f [2] 0c 37 [2] 4b 35 [2] 0c 24 [2] 42 28 [2] 4e 22 [2] 59 29 [2] 42 67 [2] 7f }

  condition:
    any of them
}