rule TTP_XOR_MULT_DOSStub_0cf2 {
  strings:
    $key_0cf2 = { 58 9a [2] 2c 82 [2] 6b 80 [2] 2c 91 [2] 62 9d [2] 6e 97 [2] 79 9c [2] 62 d2 [2] 5f }

  condition:
    any of them
}