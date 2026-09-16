rule TTP_XOR_MULT_DOSStub_cd8b {
  strings:
    $key_cd8b = { 99 e3 [2] ed fb [2] aa f9 [2] ed e8 [2] a3 e4 [2] af ee [2] b8 e5 [2] a3 ab [2] 9e }

  condition:
    any of them
}