rule TTP_XOR_MULT_DOSStub_55d2 {
  strings:
    $key_55d2 = { 01 ba [2] 75 a2 [2] 32 a0 [2] 75 b1 [2] 3b bd [2] 37 b7 [2] 20 bc [2] 3b f2 [2] 06 }

  condition:
    any of them
}