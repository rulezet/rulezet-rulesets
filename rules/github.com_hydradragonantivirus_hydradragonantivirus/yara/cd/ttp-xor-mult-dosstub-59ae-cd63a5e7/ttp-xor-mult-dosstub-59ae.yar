rule TTP_XOR_MULT_DOSStub_59ae {
  strings:
    $key_59ae = { 0d c6 [2] 79 de [2] 3e dc [2] 79 cd [2] 37 c1 [2] 3b cb [2] 2c c0 [2] 37 8e [2] 0a }

  condition:
    any of them
}