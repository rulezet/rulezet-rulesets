rule TTP_XOR_MULT_DOSStub_fc17 {
  strings:
    $key_fc17 = { a8 7f [2] dc 67 [2] 9b 65 [2] dc 74 [2] 92 78 [2] 9e 72 [2] 89 79 [2] 92 37 [2] af }

  condition:
    any of them
}