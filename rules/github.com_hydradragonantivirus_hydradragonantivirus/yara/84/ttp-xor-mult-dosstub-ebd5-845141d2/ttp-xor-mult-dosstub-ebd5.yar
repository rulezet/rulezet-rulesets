rule TTP_XOR_MULT_DOSStub_ebd5 {
  strings:
    $key_ebd5 = { bf bd [2] cb a5 [2] 8c a7 [2] cb b6 [2] 85 ba [2] 89 b0 [2] 9e bb [2] 85 f5 [2] b8 }

  condition:
    any of them
}