rule TTP_XOR_MULT_DOSStub_cdd7 {
  strings:
    $key_cdd7 = { 99 bf [2] ed a7 [2] aa a5 [2] ed b4 [2] a3 b8 [2] af b2 [2] b8 b9 [2] a3 f7 [2] 9e }

  condition:
    any of them
}