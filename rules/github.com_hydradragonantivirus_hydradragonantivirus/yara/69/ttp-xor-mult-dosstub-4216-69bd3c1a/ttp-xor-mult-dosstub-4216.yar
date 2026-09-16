rule TTP_XOR_MULT_DOSStub_4216 {
  strings:
    $key_4216 = { 16 7e [2] 62 66 [2] 25 64 [2] 62 75 [2] 2c 79 [2] 20 73 [2] 37 78 [2] 2c 36 [2] 11 }

  condition:
    any of them
}