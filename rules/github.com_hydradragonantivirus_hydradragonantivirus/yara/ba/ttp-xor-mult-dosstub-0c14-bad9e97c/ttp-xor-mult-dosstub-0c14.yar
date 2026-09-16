rule TTP_XOR_MULT_DOSStub_0c14 {
  strings:
    $key_0c14 = { 58 7c [2] 2c 64 [2] 6b 66 [2] 2c 77 [2] 62 7b [2] 6e 71 [2] 79 7a [2] 62 34 [2] 5f }

  condition:
    any of them
}