rule TTP_XOR_MULT_DOSStub_fc61 {
  strings:
    $key_fc61 = { a8 09 [2] dc 11 [2] 9b 13 [2] dc 02 [2] 92 0e [2] 9e 04 [2] 89 0f [2] 92 41 [2] af }

  condition:
    any of them
}