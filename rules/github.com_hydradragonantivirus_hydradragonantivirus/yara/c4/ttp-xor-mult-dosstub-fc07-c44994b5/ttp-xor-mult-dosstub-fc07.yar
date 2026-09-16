rule TTP_XOR_MULT_DOSStub_fc07 {
  strings:
    $key_fc07 = { a8 6f [2] dc 77 [2] 9b 75 [2] dc 64 [2] 92 68 [2] 9e 62 [2] 89 69 [2] 92 27 [2] af }

  condition:
    any of them
}