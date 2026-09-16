rule TTP_XOR_MULT_DOSStub_2c51 {
  strings:
    $key_2c51 = { 78 39 [2] 0c 21 [2] 4b 23 [2] 0c 32 [2] 42 3e [2] 4e 34 [2] 59 3f [2] 42 71 [2] 7f }

  condition:
    any of them
}