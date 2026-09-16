rule TTP_XOR_MULT_DOSStub_2c70 {
  strings:
    $key_2c70 = { 78 18 [2] 0c 00 [2] 4b 02 [2] 0c 13 [2] 42 1f [2] 4e 15 [2] 59 1e [2] 42 50 [2] 7f }

  condition:
    any of them
}