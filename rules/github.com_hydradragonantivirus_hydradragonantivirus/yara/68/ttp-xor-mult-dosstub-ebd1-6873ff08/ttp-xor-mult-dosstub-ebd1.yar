rule TTP_XOR_MULT_DOSStub_ebd1 {
  strings:
    $key_ebd1 = { bf b9 [2] cb a1 [2] 8c a3 [2] cb b2 [2] 85 be [2] 89 b4 [2] 9e bf [2] 85 f1 [2] b8 }

  condition:
    any of them
}