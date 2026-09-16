rule TTP_XOR_MULT_DOSStub_29a5 {
  strings:
    $key_29a5 = { 7d cd [2] 09 d5 [2] 4e d7 [2] 09 c6 [2] 47 ca [2] 4b c0 [2] 5c cb [2] 47 85 [2] 7a }

  condition:
    any of them
}