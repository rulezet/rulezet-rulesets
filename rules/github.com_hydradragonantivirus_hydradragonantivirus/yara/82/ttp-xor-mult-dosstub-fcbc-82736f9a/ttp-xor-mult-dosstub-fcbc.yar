rule TTP_XOR_MULT_DOSStub_fcbc {
  strings:
    $key_fcbc = { a8 d4 [2] dc cc [2] 9b ce [2] dc df [2] 92 d3 [2] 9e d9 [2] 89 d2 [2] 92 9c [2] af }

  condition:
    any of them
}