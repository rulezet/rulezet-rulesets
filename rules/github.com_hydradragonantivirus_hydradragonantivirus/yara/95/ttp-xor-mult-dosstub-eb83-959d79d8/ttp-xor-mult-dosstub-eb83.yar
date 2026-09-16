rule TTP_XOR_MULT_DOSStub_eb83 {
  strings:
    $key_eb83 = { bf eb [2] cb f3 [2] 8c f1 [2] cb e0 [2] 85 ec [2] 89 e6 [2] 9e ed [2] 85 a3 [2] b8 }

  condition:
    any of them
}