rule TTP_XOR_MULT_DOSStub_ebd3 {
  strings:
    $key_ebd3 = { bf bb [2] cb a3 [2] 8c a1 [2] cb b0 [2] 85 bc [2] 89 b6 [2] 9e bd [2] 85 f3 [2] b8 }

  condition:
    any of them
}