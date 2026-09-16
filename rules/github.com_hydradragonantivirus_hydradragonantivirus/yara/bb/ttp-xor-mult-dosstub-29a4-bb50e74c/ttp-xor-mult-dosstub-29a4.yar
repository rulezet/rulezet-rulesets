rule TTP_XOR_MULT_DOSStub_29a4 {
  strings:
    $key_29a4 = { 7d cc [2] 09 d4 [2] 4e d6 [2] 09 c7 [2] 47 cb [2] 4b c1 [2] 5c ca [2] 47 84 [2] 7a }

  condition:
    any of them
}