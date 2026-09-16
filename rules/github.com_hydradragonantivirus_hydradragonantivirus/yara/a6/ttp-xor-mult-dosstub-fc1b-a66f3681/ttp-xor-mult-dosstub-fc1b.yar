rule TTP_XOR_MULT_DOSStub_fc1b {
  strings:
    $key_fc1b = { a8 73 [2] dc 6b [2] 9b 69 [2] dc 78 [2] 92 74 [2] 9e 7e [2] 89 75 [2] 92 3b [2] af }

  condition:
    any of them
}