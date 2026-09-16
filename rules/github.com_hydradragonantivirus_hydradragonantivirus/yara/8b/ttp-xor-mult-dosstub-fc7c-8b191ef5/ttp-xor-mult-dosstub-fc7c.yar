rule TTP_XOR_MULT_DOSStub_fc7c {
  strings:
    $key_fc7c = { a8 14 [2] dc 0c [2] 9b 0e [2] dc 1f [2] 92 13 [2] 9e 19 [2] 89 12 [2] 92 5c [2] af }

  condition:
    any of them
}