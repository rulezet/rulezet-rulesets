rule TTP_XOR_MULT_DOSStub_fc79 {
  strings:
    $key_fc79 = { a8 11 [2] dc 09 [2] 9b 0b [2] dc 1a [2] 92 16 [2] 9e 1c [2] 89 17 [2] 92 59 [2] af }

  condition:
    any of them
}