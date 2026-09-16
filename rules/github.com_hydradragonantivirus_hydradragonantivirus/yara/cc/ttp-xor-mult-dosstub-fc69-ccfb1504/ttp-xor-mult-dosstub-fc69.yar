rule TTP_XOR_MULT_DOSStub_fc69 {
  strings:
    $key_fc69 = { a8 01 [2] dc 19 [2] 9b 1b [2] dc 0a [2] 92 06 [2] 9e 0c [2] 89 07 [2] 92 49 [2] af }

  condition:
    any of them
}