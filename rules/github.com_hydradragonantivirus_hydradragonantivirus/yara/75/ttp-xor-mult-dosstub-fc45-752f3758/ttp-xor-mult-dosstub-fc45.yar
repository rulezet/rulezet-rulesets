rule TTP_XOR_MULT_DOSStub_fc45 {
  strings:
    $key_fc45 = { a8 2d [2] dc 35 [2] 9b 37 [2] dc 26 [2] 92 2a [2] 9e 20 [2] 89 2b [2] 92 65 [2] af }

  condition:
    any of them
}