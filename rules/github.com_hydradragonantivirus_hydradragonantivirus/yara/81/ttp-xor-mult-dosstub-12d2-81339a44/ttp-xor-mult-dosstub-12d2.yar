rule TTP_XOR_MULT_DOSStub_12d2 {
  strings:
    $key_12d2 = { 46 ba [2] 32 a2 [2] 75 a0 [2] 32 b1 [2] 7c bd [2] 70 b7 [2] 67 bc [2] 7c f2 [2] 41 }

  condition:
    any of them
}