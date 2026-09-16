rule TTP_XOR_MULT_DOSStub_0ced {
  strings:
    $key_0ced = { 58 85 [2] 2c 9d [2] 6b 9f [2] 2c 8e [2] 62 82 [2] 6e 88 [2] 79 83 [2] 62 cd [2] 5f }

  condition:
    any of them
}