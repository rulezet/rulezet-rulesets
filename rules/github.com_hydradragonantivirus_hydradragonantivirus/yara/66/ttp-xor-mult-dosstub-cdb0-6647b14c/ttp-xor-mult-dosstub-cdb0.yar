rule TTP_XOR_MULT_DOSStub_cdb0 {
  strings:
    $key_cdb0 = { 99 d8 [2] ed c0 [2] aa c2 [2] ed d3 [2] a3 df [2] af d5 [2] b8 de [2] a3 90 [2] 9e }

  condition:
    any of them
}