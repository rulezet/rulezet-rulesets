rule TTP_XOR_MULT_DOSStub_eb9d {
  strings:
    $key_eb9d = { bf f5 [2] cb ed [2] 8c ef [2] cb fe [2] 85 f2 [2] 89 f8 [2] 9e f3 [2] 85 bd [2] b8 }

  condition:
    any of them
}