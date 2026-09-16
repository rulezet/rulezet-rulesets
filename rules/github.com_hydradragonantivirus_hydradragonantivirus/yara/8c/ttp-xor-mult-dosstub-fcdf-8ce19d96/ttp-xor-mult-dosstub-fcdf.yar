rule TTP_XOR_MULT_DOSStub_fcdf {
  strings:
    $key_fcdf = { a8 b7 [2] dc af [2] 9b ad [2] dc bc [2] 92 b0 [2] 9e ba [2] 89 b1 [2] 92 ff [2] af }

  condition:
    any of them
}