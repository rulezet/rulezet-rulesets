rule TTP_XOR_MULT_DOSStub_fc6a {
  strings:
    $key_fc6a = { a8 02 [2] dc 1a [2] 9b 18 [2] dc 09 [2] 92 05 [2] 9e 0f [2] 89 04 [2] 92 4a [2] af }

  condition:
    any of them
}