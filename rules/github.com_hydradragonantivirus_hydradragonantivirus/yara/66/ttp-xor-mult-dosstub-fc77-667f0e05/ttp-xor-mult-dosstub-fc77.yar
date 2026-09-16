rule TTP_XOR_MULT_DOSStub_fc77 {
  strings:
    $key_fc77 = { a8 1f [2] dc 07 [2] 9b 05 [2] dc 14 [2] 92 18 [2] 9e 12 [2] 89 19 [2] 92 57 [2] af }

  condition:
    any of them
}