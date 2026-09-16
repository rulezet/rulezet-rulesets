rule TTP_XOR_MULT_DOSStub_2c78 {
  strings:
    $key_2c78 = { 78 10 [2] 0c 08 [2] 4b 0a [2] 0c 1b [2] 42 17 [2] 4e 1d [2] 59 16 [2] 42 58 [2] 7f }

  condition:
    any of them
}