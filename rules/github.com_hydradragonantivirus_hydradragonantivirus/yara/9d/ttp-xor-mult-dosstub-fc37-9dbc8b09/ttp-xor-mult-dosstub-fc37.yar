rule TTP_XOR_MULT_DOSStub_fc37 {
  strings:
    $key_fc37 = { a8 5f [2] dc 47 [2] 9b 45 [2] dc 54 [2] 92 58 [2] 9e 52 [2] 89 59 [2] 92 17 [2] af }

  condition:
    any of them
}