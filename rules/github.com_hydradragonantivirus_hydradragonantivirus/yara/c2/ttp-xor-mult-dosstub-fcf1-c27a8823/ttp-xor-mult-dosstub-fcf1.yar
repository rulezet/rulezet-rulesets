rule TTP_XOR_MULT_DOSStub_fcf1 {
  strings:
    $key_fcf1 = { a8 99 [2] dc 81 [2] 9b 83 [2] dc 92 [2] 92 9e [2] 9e 94 [2] 89 9f [2] 92 d1 [2] af }

  condition:
    any of them
}