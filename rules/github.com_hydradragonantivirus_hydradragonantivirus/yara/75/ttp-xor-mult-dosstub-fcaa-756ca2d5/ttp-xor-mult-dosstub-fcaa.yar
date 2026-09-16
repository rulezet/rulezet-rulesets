rule TTP_XOR_MULT_DOSStub_fcaa {
  strings:
    $key_fcaa = { a8 c2 [2] dc da [2] 9b d8 [2] dc c9 [2] 92 c5 [2] 9e cf [2] 89 c4 [2] 92 8a [2] af }

  condition:
    any of them
}