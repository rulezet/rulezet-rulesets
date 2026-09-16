rule TTP_XOR_MULT_DOSStub_75d2 {
  strings:
    $key_75d2 = { 21 ba [2] 55 a2 [2] 12 a0 [2] 55 b1 [2] 1b bd [2] 17 b7 [2] 00 bc [2] 1b f2 [2] 26 }

  condition:
    any of them
}