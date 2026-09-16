rule TTP_XOR_MULT_DOSStub_59a5 {
  strings:
    $key_59a5 = { 0d cd [2] 79 d5 [2] 3e d7 [2] 79 c6 [2] 37 ca [2] 3b c0 [2] 2c cb [2] 37 85 [2] 0a }

  condition:
    any of them
}