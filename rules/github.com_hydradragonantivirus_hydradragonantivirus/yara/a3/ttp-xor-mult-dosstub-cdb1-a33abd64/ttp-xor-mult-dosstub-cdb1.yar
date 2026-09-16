rule TTP_XOR_MULT_DOSStub_cdb1 {
  strings:
    $key_cdb1 = { 99 d9 [2] ed c1 [2] aa c3 [2] ed d2 [2] a3 de [2] af d4 [2] b8 df [2] a3 91 [2] 9e }

  condition:
    any of them
}