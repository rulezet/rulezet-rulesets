rule TTP_XOR_MULT_DOSStub_8fc4 {
  strings:
    $key_8fc4 = { db ac [2] af b4 [2] e8 b6 [2] af a7 [2] e1 ab [2] ed a1 [2] fa aa [2] e1 e4 [2] dc }

  condition:
    any of them
}