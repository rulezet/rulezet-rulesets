rule TTP_XOR_MULT_DOSStub_cdd3 {
  strings:
    $key_cdd3 = { 99 bb [2] ed a3 [2] aa a1 [2] ed b0 [2] a3 bc [2] af b6 [2] b8 bd [2] a3 f3 [2] 9e }

  condition:
    any of them
}