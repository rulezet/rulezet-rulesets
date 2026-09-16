rule TTP_XOR_MULT_DOSStub_19a5 {
  strings:
    $key_19a5 = { 4d cd [2] 39 d5 [2] 7e d7 [2] 39 c6 [2] 77 ca [2] 7b c0 [2] 6c cb [2] 77 85 [2] 4a }

  condition:
    any of them
}