rule TTP_XOR_MULT_DOSStub_fcda {
  strings:
    $key_fcda = { a8 b2 [2] dc aa [2] 9b a8 [2] dc b9 [2] 92 b5 [2] 9e bf [2] 89 b4 [2] 92 fa [2] af }

  condition:
    any of them
}