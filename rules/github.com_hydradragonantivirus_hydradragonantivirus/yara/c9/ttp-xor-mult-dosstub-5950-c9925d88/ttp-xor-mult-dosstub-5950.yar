rule TTP_XOR_MULT_DOSStub_5950 {
  strings:
    $key_5950 = { 0d 38 [2] 79 20 [2] 3e 22 [2] 79 33 [2] 37 3f [2] 3b 35 [2] 2c 3e [2] 37 70 [2] 0a }

  condition:
    any of them
}