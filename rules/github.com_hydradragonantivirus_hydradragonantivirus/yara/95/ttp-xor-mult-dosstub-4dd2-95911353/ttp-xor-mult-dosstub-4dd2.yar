rule TTP_XOR_MULT_DOSStub_4dd2 {
  strings:
    $key_4dd2 = { 19 ba [2] 6d a2 [2] 2a a0 [2] 6d b1 [2] 23 bd [2] 2f b7 [2] 38 bc [2] 23 f2 [2] 1e }

  condition:
    any of them
}