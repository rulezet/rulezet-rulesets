rule TTP_XOR_MULT_DOSStub_fc54 {
  strings:
    $key_fc54 = { a8 3c [2] dc 24 [2] 9b 26 [2] dc 37 [2] 92 3b [2] 9e 31 [2] 89 3a [2] 92 74 [2] af }

  condition:
    any of them
}