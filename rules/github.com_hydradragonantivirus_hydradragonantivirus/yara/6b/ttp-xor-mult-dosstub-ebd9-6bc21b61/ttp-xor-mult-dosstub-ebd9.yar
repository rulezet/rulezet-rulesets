rule TTP_XOR_MULT_DOSStub_ebd9 {
  strings:
    $key_ebd9 = { bf b1 [2] cb a9 [2] 8c ab [2] cb ba [2] 85 b6 [2] 89 bc [2] 9e b7 [2] 85 f9 [2] b8 }

  condition:
    any of them
}