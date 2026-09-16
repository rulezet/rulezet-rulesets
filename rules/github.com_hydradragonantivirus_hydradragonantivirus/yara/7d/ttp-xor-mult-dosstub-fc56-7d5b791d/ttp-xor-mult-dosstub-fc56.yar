rule TTP_XOR_MULT_DOSStub_fc56 {
  strings:
    $key_fc56 = { a8 3e [2] dc 26 [2] 9b 24 [2] dc 35 [2] 92 39 [2] 9e 33 [2] 89 38 [2] 92 76 [2] af }

  condition:
    any of them
}