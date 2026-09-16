rule TTP_XOR_MULT_DOSStub_fc71 {
  strings:
    $key_fc71 = { a8 19 [2] dc 01 [2] 9b 03 [2] dc 12 [2] 92 1e [2] 9e 14 [2] 89 1f [2] 92 51 [2] af }

  condition:
    any of them
}