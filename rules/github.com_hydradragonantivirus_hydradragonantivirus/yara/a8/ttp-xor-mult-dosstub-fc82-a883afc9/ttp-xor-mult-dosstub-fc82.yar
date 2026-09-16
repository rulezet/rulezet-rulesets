rule TTP_XOR_MULT_DOSStub_fc82 {
  strings:
    $key_fc82 = { a8 ea [2] dc f2 [2] 9b f0 [2] dc e1 [2] 92 ed [2] 9e e7 [2] 89 ec [2] 92 a2 [2] af }

  condition:
    any of them
}