rule TTP_XOR_MULT_DOSStub_09a5 {
  strings:
    $key_09a5 = { 5d cd [2] 29 d5 [2] 6e d7 [2] 29 c6 [2] 67 ca [2] 6b c0 [2] 7c cb [2] 67 85 [2] 5a }

  condition:
    any of them
}