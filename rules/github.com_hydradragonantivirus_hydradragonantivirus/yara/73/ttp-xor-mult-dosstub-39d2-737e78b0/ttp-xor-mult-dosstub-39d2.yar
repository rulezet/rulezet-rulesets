rule TTP_XOR_MULT_DOSStub_39d2 {
  strings:
    $key_39d2 = { 6d ba [2] 19 a2 [2] 5e a0 [2] 19 b1 [2] 57 bd [2] 5b b7 [2] 4c bc [2] 57 f2 [2] 6a }

  condition:
    any of them
}