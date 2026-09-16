rule TTP_XOR_MULT_DOSStub_3dd2 {
  strings:
    $key_3dd2 = { 69 ba [2] 1d a2 [2] 5a a0 [2] 1d b1 [2] 53 bd [2] 5f b7 [2] 48 bc [2] 53 f2 [2] 6e }

  condition:
    any of them
}