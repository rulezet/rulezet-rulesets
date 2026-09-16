rule TTP_XOR_MULT_DOSStub_72d2 {
  strings:
    $key_72d2 = { 26 ba [2] 52 a2 [2] 15 a0 [2] 52 b1 [2] 1c bd [2] 10 b7 [2] 07 bc [2] 1c f2 [2] 21 }

  condition:
    any of them
}