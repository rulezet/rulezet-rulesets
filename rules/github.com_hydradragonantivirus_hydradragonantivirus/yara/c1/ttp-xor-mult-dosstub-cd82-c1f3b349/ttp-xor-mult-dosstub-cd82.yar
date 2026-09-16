rule TTP_XOR_MULT_DOSStub_cd82 {
  strings:
    $key_cd82 = { 99 ea [2] ed f2 [2] aa f0 [2] ed e1 [2] a3 ed [2] af e7 [2] b8 ec [2] a3 a2 [2] 9e }

  condition:
    any of them
}