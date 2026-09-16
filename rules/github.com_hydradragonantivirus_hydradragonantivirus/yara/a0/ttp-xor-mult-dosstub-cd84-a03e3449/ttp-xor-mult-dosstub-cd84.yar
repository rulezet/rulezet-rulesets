rule TTP_XOR_MULT_DOSStub_cd84 {
  strings:
    $key_cd84 = { 99 ec [2] ed f4 [2] aa f6 [2] ed e7 [2] a3 eb [2] af e1 [2] b8 ea [2] a3 a4 [2] 9e }

  condition:
    any of them
}