rule TTP_XOR_MULT_DOSStub_3cae {
  strings:
    $key_3cae = { 68 c6 [2] 1c de [2] 5b dc [2] 1c cd [2] 52 c1 [2] 5e cb [2] 49 c0 [2] 52 8e [2] 6f }

  condition:
    any of them
}