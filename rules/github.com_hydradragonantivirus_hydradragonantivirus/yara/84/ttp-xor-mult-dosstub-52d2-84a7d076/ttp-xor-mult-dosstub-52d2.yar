rule TTP_XOR_MULT_DOSStub_52d2 {
  strings:
    $key_52d2 = { 06 ba [2] 72 a2 [2] 35 a0 [2] 72 b1 [2] 3c bd [2] 30 b7 [2] 27 bc [2] 3c f2 [2] 01 }

  condition:
    any of them
}