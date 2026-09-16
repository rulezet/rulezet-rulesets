rule TTP_XOR_MULT_DOSStub_39a5 {
  strings:
    $key_39a5 = { 6d cd [2] 19 d5 [2] 5e d7 [2] 19 c6 [2] 57 ca [2] 5b c0 [2] 4c cb [2] 57 85 [2] 6a }

  condition:
    any of them
}