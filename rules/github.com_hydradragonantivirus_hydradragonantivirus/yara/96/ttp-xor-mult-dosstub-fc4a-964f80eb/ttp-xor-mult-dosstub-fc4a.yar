rule TTP_XOR_MULT_DOSStub_fc4a {
  strings:
    $key_fc4a = { a8 22 [2] dc 3a [2] 9b 38 [2] dc 29 [2] 92 25 [2] 9e 2f [2] 89 24 [2] 92 6a [2] af }

  condition:
    any of them
}