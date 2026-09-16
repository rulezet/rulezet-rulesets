rule TTP_XOR_MULT_DOSStub_fc11 {
  strings:
    $key_fc11 = { a8 79 [2] dc 61 [2] 9b 63 [2] dc 72 [2] 92 7e [2] 9e 74 [2] 89 7f [2] 92 31 [2] af }

  condition:
    any of them
}