rule TTP_XOR_MULT_DOSStub_fc29 {
  strings:
    $key_fc29 = { a8 41 [2] dc 59 [2] 9b 5b [2] dc 4a [2] 92 46 [2] 9e 4c [2] 89 47 [2] 92 09 [2] af }

  condition:
    any of them
}