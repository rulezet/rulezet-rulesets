rule TTP_XOR_MULT_DOSStub_2c16 {
  strings:
    $key_2c16 = { 78 7e [2] 0c 66 [2] 4b 64 [2] 0c 75 [2] 42 79 [2] 4e 73 [2] 59 78 [2] 42 36 [2] 7f }

  condition:
    any of them
}