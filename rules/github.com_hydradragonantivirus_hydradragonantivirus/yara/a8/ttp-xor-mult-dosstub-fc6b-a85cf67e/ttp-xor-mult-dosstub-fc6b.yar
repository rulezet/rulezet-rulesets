rule TTP_XOR_MULT_DOSStub_fc6b {
  strings:
    $key_fc6b = { a8 03 [2] dc 1b [2] 9b 19 [2] dc 08 [2] 92 04 [2] 9e 0e [2] 89 05 [2] 92 4b [2] af }

  condition:
    any of them
}