rule TTP_XOR_MULT_DOSStub_fc36 {
  strings:
    $key_fc36 = { a8 5e [2] dc 46 [2] 9b 44 [2] dc 55 [2] 92 59 [2] 9e 53 [2] 89 58 [2] 92 16 [2] af }

  condition:
    any of them
}