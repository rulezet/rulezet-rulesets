rule TTP_XOR_MULT_DOSStub_fc19 {
  strings:
    $key_fc19 = { a8 71 [2] dc 69 [2] 9b 6b [2] dc 7a [2] 92 76 [2] 9e 7c [2] 89 77 [2] 92 39 [2] af }

  condition:
    any of them
}