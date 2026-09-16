rule TTP_XOR_MULT_DOSStub_2c56 {
  strings:
    $key_2c56 = { 78 3e [2] 0c 26 [2] 4b 24 [2] 0c 35 [2] 42 39 [2] 4e 33 [2] 59 38 [2] 42 76 [2] 7f }

  condition:
    any of them
}