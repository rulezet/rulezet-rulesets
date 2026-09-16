rule TTP_XOR_MULT_DOSStub_fc4b {
  strings:
    $key_fc4b = { a8 23 [2] dc 3b [2] 9b 39 [2] dc 28 [2] 92 24 [2] 9e 2e [2] 89 25 [2] 92 6b [2] af }

  condition:
    any of them
}