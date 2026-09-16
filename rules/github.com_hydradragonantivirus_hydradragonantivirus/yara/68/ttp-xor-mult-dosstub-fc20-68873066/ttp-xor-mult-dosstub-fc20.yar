rule TTP_XOR_MULT_DOSStub_fc20 {
  strings:
    $key_fc20 = { a8 48 [2] dc 50 [2] 9b 52 [2] dc 43 [2] 92 4f [2] 9e 45 [2] 89 4e [2] 92 00 [2] af }

  condition:
    any of them
}