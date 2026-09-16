rule TTP_XOR_MULT_DOSStub_fc27 {
  strings:
    $key_fc27 = { a8 4f [2] dc 57 [2] 9b 55 [2] dc 44 [2] 92 48 [2] 9e 42 [2] 89 49 [2] 92 07 [2] af }

  condition:
    any of them
}