rule TTP_XOR_MULT_DOSStub_fcf0 {
  strings:
    $key_fcf0 = { a8 98 [2] dc 80 [2] 9b 82 [2] dc 93 [2] 92 9f [2] 9e 95 [2] 89 9e [2] 92 d0 [2] af }

  condition:
    any of them
}