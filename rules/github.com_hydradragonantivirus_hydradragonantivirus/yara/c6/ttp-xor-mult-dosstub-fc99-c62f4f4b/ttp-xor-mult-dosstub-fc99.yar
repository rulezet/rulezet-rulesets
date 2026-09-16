rule TTP_XOR_MULT_DOSStub_fc99 {
  strings:
    $key_fc99 = { a8 f1 [2] dc e9 [2] 9b eb [2] dc fa [2] 92 f6 [2] 9e fc [2] 89 f7 [2] 92 b9 [2] af }

  condition:
    any of them
}