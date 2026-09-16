rule TTP_XOR_MULT_DOSStub_0c35 {
  strings:
    $key_0c35 = { 58 5d [2] 2c 45 [2] 6b 47 [2] 2c 56 [2] 62 5a [2] 6e 50 [2] 79 5b [2] 62 15 [2] 5f }

  condition:
    any of them
}