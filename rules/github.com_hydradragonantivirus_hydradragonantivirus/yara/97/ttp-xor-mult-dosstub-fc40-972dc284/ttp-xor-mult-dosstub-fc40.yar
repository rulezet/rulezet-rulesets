rule TTP_XOR_MULT_DOSStub_fc40 {
  strings:
    $key_fc40 = { a8 28 [2] dc 30 [2] 9b 32 [2] dc 23 [2] 92 2f [2] 9e 25 [2] 89 2e [2] 92 60 [2] af }

  condition:
    any of them
}