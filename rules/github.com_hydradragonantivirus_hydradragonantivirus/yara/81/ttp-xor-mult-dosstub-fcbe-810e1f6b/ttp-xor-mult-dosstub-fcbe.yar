rule TTP_XOR_MULT_DOSStub_fcbe {
  strings:
    $key_fcbe = { a8 d6 [2] dc ce [2] 9b cc [2] dc dd [2] 92 d1 [2] 9e db [2] 89 d0 [2] 92 9e [2] af }

  condition:
    any of them
}