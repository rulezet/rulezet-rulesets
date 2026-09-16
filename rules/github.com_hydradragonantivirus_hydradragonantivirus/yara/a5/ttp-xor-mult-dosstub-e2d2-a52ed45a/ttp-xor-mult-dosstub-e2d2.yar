rule TTP_XOR_MULT_DOSStub_e2d2 {
  strings:
    $key_e2d2 = { b6 ba [2] c2 a2 [2] 85 a0 [2] c2 b1 [2] 8c bd [2] 80 b7 [2] 97 bc [2] 8c f2 [2] b1 }

  condition:
    any of them
}