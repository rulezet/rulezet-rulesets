rule TTP_XOR_MULT_DOSStub_0c13 {
  strings:
    $key_0c13 = { 58 7b [2] 2c 63 [2] 6b 61 [2] 2c 70 [2] 62 7c [2] 6e 76 [2] 79 7d [2] 62 33 [2] 5f }

  condition:
    any of them
}