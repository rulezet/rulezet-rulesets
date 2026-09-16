rule TTP_XOR_MULT_DOSStub_f9b9 {
  strings:
    $key_f9b9 = { ad d1 [2] d9 c9 [2] 9e cb [2] d9 da [2] 97 d6 [2] 9b dc [2] 8c d7 [2] 97 99 [2] aa }

  condition:
    any of them
}