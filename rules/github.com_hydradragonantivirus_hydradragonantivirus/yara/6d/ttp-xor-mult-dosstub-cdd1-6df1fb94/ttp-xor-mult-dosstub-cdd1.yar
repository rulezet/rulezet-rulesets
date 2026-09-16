rule TTP_XOR_MULT_DOSStub_cdd1 {
  strings:
    $key_cdd1 = { 99 b9 [2] ed a1 [2] aa a3 [2] ed b2 [2] a3 be [2] af b4 [2] b8 bf [2] a3 f1 [2] 9e }

  condition:
    any of them
}