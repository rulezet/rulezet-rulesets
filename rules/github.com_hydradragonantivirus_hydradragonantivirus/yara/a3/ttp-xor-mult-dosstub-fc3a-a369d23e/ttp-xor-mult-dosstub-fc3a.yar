rule TTP_XOR_MULT_DOSStub_fc3a {
  strings:
    $key_fc3a = { a8 52 [2] dc 4a [2] 9b 48 [2] dc 59 [2] 92 55 [2] 9e 5f [2] 89 54 [2] 92 1a [2] af }

  condition:
    any of them
}