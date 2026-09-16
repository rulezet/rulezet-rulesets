rule TTP_XOR_MULT_DOSStub_39b9 {
  strings:
    $key_39b9 = { 6d d1 [2] 19 c9 [2] 5e cb [2] 19 da [2] 57 d6 [2] 5b dc [2] 4c d7 [2] 57 99 [2] 6a }

  condition:
    any of them
}