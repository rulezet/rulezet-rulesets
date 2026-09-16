rule TTP_XOR_MULT_DOSStub_eb9e {
  strings:
    $key_eb9e = { bf f6 [2] cb ee [2] 8c ec [2] cb fd [2] 85 f1 [2] 89 fb [2] 9e f0 [2] 85 be [2] b8 }

  condition:
    any of them
}