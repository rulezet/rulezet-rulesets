rule TTP_XOR_MULT_DOSStub_fc83 {
  strings:
    $key_fc83 = { a8 eb [2] dc f3 [2] 9b f1 [2] dc e0 [2] 92 ec [2] 9e e6 [2] 89 ed [2] 92 a3 [2] af }

  condition:
    any of them
}