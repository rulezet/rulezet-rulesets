rule TTP_XOR_MULT_DOSStub_ebd2 {
  strings:
    $key_ebd2 = { bf ba [2] cb a2 [2] 8c a0 [2] cb b1 [2] 85 bd [2] 89 b7 [2] 9e bc [2] 85 f2 [2] b8 }

  condition:
    any of them
}