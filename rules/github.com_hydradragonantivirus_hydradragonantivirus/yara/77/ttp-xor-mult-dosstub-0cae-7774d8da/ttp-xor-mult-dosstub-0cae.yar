rule TTP_XOR_MULT_DOSStub_0cae {
  strings:
    $key_0cae = { 58 c6 [2] 2c de [2] 6b dc [2] 2c cd [2] 62 c1 [2] 6e cb [2] 79 c0 [2] 62 8e [2] 5f }

  condition:
    any of them
}