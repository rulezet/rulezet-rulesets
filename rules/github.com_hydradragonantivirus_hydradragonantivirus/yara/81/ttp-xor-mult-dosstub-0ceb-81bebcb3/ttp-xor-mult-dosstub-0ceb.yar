rule TTP_XOR_MULT_DOSStub_0ceb {
  strings:
    $key_0ceb = { 58 83 [2] 2c 9b [2] 6b 99 [2] 2c 88 [2] 62 84 [2] 6e 8e [2] 79 85 [2] 62 cb [2] 5f }

  condition:
    any of them
}