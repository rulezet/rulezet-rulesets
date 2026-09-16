rule TTP_XOR_MULT_DOSStub_22d2 {
  strings:
    $key_22d2 = { 76 ba [2] 02 a2 [2] 45 a0 [2] 02 b1 [2] 4c bd [2] 40 b7 [2] 57 bc [2] 4c f2 [2] 71 }

  condition:
    any of them
}