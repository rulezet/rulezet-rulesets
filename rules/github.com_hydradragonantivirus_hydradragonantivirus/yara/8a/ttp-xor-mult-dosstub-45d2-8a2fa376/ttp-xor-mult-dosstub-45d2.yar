rule TTP_XOR_MULT_DOSStub_45d2 {
  strings:
    $key_45d2 = { 11 ba [2] 65 a2 [2] 22 a0 [2] 65 b1 [2] 2b bd [2] 27 b7 [2] 30 bc [2] 2b f2 [2] 16 }

  condition:
    any of them
}