rule TTP_XOR_MULT_DOSStub_fc15 {
  strings:
    $key_fc15 = { a8 7d [2] dc 65 [2] 9b 67 [2] dc 76 [2] 92 7a [2] 9e 70 [2] 89 7b [2] 92 35 [2] af }

  condition:
    any of them
}