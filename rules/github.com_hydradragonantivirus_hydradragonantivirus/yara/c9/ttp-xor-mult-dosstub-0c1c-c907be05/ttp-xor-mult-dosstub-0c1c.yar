rule TTP_XOR_MULT_DOSStub_0c1c {
  strings:
    $key_0c1c = { 58 74 [2] 2c 6c [2] 6b 6e [2] 2c 7f [2] 62 73 [2] 6e 79 [2] 79 72 [2] 62 3c [2] 5f }

  condition:
    any of them
}