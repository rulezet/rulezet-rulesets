rule TTP_XOR_MULT_DOSStub_cd98 {
  strings:
    $key_cd98 = { 99 f0 [2] ed e8 [2] aa ea [2] ed fb [2] a3 f7 [2] af fd [2] b8 f6 [2] a3 b8 [2] 9e }

  condition:
    any of them
}