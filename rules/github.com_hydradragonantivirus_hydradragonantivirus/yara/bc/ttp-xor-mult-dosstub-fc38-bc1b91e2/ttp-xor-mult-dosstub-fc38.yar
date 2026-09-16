rule TTP_XOR_MULT_DOSStub_fc38 {
  strings:
    $key_fc38 = { a8 50 [2] dc 48 [2] 9b 4a [2] dc 5b [2] 92 57 [2] 9e 5d [2] 89 56 [2] 92 18 [2] af }

  condition:
    any of them
}