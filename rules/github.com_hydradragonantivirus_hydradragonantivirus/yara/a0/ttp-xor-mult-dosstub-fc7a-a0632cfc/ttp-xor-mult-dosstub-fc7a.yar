rule TTP_XOR_MULT_DOSStub_fc7a {
  strings:
    $key_fc7a = { a8 12 [2] dc 0a [2] 9b 08 [2] dc 19 [2] 92 15 [2] 9e 1f [2] 89 14 [2] 92 5a [2] af }

  condition:
    any of them
}