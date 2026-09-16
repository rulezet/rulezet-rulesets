rule TTP_XOR_MULT_DOSStub_0ce1 {
  strings:
    $key_0ce1 = { 58 89 [2] 2c 91 [2] 6b 93 [2] 2c 82 [2] 62 8e [2] 6e 84 [2] 79 8f [2] 62 c1 [2] 5f }

  condition:
    any of them
}