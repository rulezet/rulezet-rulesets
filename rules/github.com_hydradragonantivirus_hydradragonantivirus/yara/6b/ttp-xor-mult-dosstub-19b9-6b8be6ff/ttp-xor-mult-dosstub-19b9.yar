rule TTP_XOR_MULT_DOSStub_19b9 {
  strings:
    $key_19b9 = { 4d d1 [2] 39 c9 [2] 7e cb [2] 39 da [2] 77 d6 [2] 7b dc [2] 6c d7 [2] 77 99 [2] 4a }

  condition:
    any of them
}