rule TTP_XOR_MULT_DOSStub_6cae {
  strings:
    $key_6cae = { 38 c6 [2] 4c de [2] 0b dc [2] 4c cd [2] 02 c1 [2] 0e cb [2] 19 c0 [2] 02 8e [2] 3f }

  condition:
    any of them
}