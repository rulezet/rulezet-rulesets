rule TTP_XOR_MULT_DOSStub_fc98 {
  strings:
    $key_fc98 = { a8 f0 [2] dc e8 [2] 9b ea [2] dc fb [2] 92 f7 [2] 9e fd [2] 89 f6 [2] 92 b8 [2] af }

  condition:
    any of them
}