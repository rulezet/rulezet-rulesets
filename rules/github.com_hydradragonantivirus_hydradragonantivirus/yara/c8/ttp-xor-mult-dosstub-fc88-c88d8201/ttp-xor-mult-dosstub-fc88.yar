rule TTP_XOR_MULT_DOSStub_fc88 {
  strings:
    $key_fc88 = { a8 e0 [2] dc f8 [2] 9b fa [2] dc eb [2] 92 e7 [2] 9e ed [2] 89 e6 [2] 92 a8 [2] af }

  condition:
    any of them
}