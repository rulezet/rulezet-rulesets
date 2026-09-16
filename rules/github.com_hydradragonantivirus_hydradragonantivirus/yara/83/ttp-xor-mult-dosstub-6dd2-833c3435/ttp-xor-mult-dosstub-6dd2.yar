rule TTP_XOR_MULT_DOSStub_6dd2 {
  strings:
    $key_6dd2 = { 39 ba [2] 4d a2 [2] 0a a0 [2] 4d b1 [2] 03 bd [2] 0f b7 [2] 18 bc [2] 03 f2 [2] 3e }

  condition:
    any of them
}