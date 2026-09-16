rule TTP_XOR_MULT_DOSStub_39a4 {
  strings:
    $key_39a4 = { 6d cc [2] 19 d4 [2] 5e d6 [2] 19 c7 [2] 57 cb [2] 5b c1 [2] 4c ca [2] 57 84 [2] 6a }

  condition:
    any of them
}