rule TTP_XOR_MULT_DOSStub_fc47 {
  strings:
    $key_fc47 = { a8 2f [2] dc 37 [2] 9b 35 [2] dc 24 [2] 92 28 [2] 9e 22 [2] 89 29 [2] 92 67 [2] af }

  condition:
    any of them
}