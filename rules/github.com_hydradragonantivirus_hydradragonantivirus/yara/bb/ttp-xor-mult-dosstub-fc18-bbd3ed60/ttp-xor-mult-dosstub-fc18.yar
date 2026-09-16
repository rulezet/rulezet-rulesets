rule TTP_XOR_MULT_DOSStub_fc18 {
  strings:
    $key_fc18 = { a8 70 [2] dc 68 [2] 9b 6a [2] dc 7b [2] 92 77 [2] 9e 7d [2] 89 76 [2] 92 38 [2] af }

  condition:
    any of them
}