rule TTP_XOR_MULT_DOSStub_fcf6 {
  strings:
    $key_fcf6 = { a8 9e [2] dc 86 [2] 9b 84 [2] dc 95 [2] 92 99 [2] 9e 93 [2] 89 98 [2] 92 d6 [2] af }

  condition:
    any of them
}