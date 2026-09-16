rule TTP_XOR_MULT_DOSStub_7dd2 {
  strings:
    $key_7dd2 = { 29 ba [2] 5d a2 [2] 1a a0 [2] 5d b1 [2] 13 bd [2] 1f b7 [2] 08 bc [2] 13 f2 [2] 2e }

  condition:
    any of them
}