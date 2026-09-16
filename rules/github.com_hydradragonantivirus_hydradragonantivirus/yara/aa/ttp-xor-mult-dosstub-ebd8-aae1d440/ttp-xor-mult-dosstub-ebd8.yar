rule TTP_XOR_MULT_DOSStub_ebd8 {
  strings:
    $key_ebd8 = { bf b0 [2] cb a8 [2] 8c aa [2] cb bb [2] 85 b7 [2] 89 bd [2] 9e b6 [2] 85 f8 [2] b8 }

  condition:
    any of them
}