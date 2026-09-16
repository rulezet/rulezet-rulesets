rule TTP_XOR_MULT_DOSStub_fc25 {
  strings:
    $key_fc25 = { a8 4d [2] dc 55 [2] 9b 57 [2] dc 46 [2] 92 4a [2] 9e 40 [2] 89 4b [2] 92 05 [2] af }

  condition:
    any of them
}