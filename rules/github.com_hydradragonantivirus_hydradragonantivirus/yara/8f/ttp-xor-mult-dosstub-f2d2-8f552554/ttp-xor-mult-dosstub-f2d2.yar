rule TTP_XOR_MULT_DOSStub_f2d2 {
  strings:
    $key_f2d2 = { a6 ba [2] d2 a2 [2] 95 a0 [2] d2 b1 [2] 9c bd [2] 90 b7 [2] 87 bc [2] 9c f2 [2] a1 }

  condition:
    any of them
}