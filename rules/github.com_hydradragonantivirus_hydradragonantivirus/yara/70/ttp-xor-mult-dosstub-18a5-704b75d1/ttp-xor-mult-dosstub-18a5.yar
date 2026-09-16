rule TTP_XOR_MULT_DOSStub_18a5 {
  strings:
    $key_18a5 = { 4c cd [2] 38 d5 [2] 7f d7 [2] 38 c6 [2] 76 ca [2] 7a c0 [2] 6d cb [2] 76 85 [2] 4b }

  condition:
    any of them
}