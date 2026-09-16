rule TTP_XOR_MULT_DOSStub_0c67 {
  strings:
    $key_0c67 = { 58 0f [2] 2c 17 [2] 6b 15 [2] 2c 04 [2] 62 08 [2] 6e 02 [2] 79 09 [2] 62 47 [2] 5f }

  condition:
    any of them
}