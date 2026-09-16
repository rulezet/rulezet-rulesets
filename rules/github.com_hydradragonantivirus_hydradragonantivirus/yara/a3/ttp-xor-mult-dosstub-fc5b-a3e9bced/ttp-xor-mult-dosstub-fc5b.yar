rule TTP_XOR_MULT_DOSStub_fc5b {
  strings:
    $key_fc5b = { a8 33 [2] dc 2b [2] 9b 29 [2] dc 38 [2] 92 34 [2] 9e 3e [2] 89 35 [2] 92 7b [2] af }

  condition:
    any of them
}