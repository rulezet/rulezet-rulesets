rule TTP_XOR_MULT_DOSStub_fc9d {
  strings:
    $key_fc9d = { a8 f5 [2] dc ed [2] 9b ef [2] dc fe [2] 92 f2 [2] 9e f8 [2] 89 f3 [2] 92 bd [2] af }

  condition:
    any of them
}