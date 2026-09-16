rule TTP_XOR_MULT_DOSStub_0c73 {
  strings:
    $key_0c73 = { 58 1b [2] 2c 03 [2] 6b 01 [2] 2c 10 [2] 62 1c [2] 6e 16 [2] 79 1d [2] 62 53 [2] 5f }

  condition:
    any of them
}