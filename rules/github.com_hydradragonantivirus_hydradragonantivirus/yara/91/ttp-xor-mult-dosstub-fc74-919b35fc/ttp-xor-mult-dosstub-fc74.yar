rule TTP_XOR_MULT_DOSStub_fc74 {
  strings:
    $key_fc74 = { a8 1c [2] dc 04 [2] 9b 06 [2] dc 17 [2] 92 1b [2] 9e 11 [2] 89 1a [2] 92 54 [2] af }

  condition:
    any of them
}