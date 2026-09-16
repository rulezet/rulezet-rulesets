rule TTP_XOR_MULT_DOSStub_32d2 {
  strings:
    $key_32d2 = { 66 ba [2] 12 a2 [2] 55 a0 [2] 12 b1 [2] 5c bd [2] 50 b7 [2] 47 bc [2] 5c f2 [2] 61 }

  condition:
    any of them
}