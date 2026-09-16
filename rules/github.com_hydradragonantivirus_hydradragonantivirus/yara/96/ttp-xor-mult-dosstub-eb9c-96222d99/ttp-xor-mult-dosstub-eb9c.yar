rule TTP_XOR_MULT_DOSStub_eb9c {
  strings:
    $key_eb9c = { bf f4 [2] cb ec [2] 8c ee [2] cb ff [2] 85 f3 [2] 89 f9 [2] 9e f2 [2] 85 bc [2] b8 }

  condition:
    any of them
}