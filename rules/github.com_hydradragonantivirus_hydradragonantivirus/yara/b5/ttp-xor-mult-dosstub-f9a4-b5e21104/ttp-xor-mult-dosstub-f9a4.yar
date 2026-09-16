rule TTP_XOR_MULT_DOSStub_f9a4 {
  strings:
    $key_f9a4 = { ad cc [2] d9 d4 [2] 9e d6 [2] d9 c7 [2] 97 cb [2] 9b c1 [2] 8c ca [2] 97 84 [2] aa }

  condition:
    any of them
}