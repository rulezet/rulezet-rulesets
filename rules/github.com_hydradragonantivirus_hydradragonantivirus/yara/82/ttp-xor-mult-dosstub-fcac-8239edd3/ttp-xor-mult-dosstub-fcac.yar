rule TTP_XOR_MULT_DOSStub_fcac {
  strings:
    $key_fcac = { a8 c4 [2] dc dc [2] 9b de [2] dc cf [2] 92 c3 [2] 9e c9 [2] 89 c2 [2] 92 8c [2] af }

  condition:
    any of them
}