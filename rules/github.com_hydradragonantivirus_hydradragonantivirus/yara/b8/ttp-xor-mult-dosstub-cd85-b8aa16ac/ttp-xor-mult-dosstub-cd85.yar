rule TTP_XOR_MULT_DOSStub_cd85 {
  strings:
    $key_cd85 = { 99 ed [2] ed f5 [2] aa f7 [2] ed e6 [2] a3 ea [2] af e0 [2] b8 eb [2] a3 a5 [2] 9e }

  condition:
    any of them
}