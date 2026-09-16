rule TTP_XOR_MULT_DOSStub_49a5 {
  strings:
    $key_49a5 = { 1d cd [2] 69 d5 [2] 2e d7 [2] 69 c6 [2] 27 ca [2] 2b c0 [2] 3c cb [2] 27 85 [2] 1a }

  condition:
    any of them
}