rule TTP_XOR_MULT_DOSStub_fc85 {
  strings:
    $key_fc85 = { a8 ed [2] dc f5 [2] 9b f7 [2] dc e6 [2] 92 ea [2] 9e e0 [2] 89 eb [2] 92 a5 [2] af }

  condition:
    any of them
}