rule TTP_XOR_MULT_DOSStub_fc1a {
  strings:
    $key_fc1a = { a8 72 [2] dc 6a [2] 9b 68 [2] dc 79 [2] 92 75 [2] 9e 7f [2] 89 74 [2] 92 3a [2] af }

  condition:
    any of them
}