rule TTP_XOR_MULT_DOSStub_7597 {
  strings:
    $key_7597 = { 21 ff [2] 55 e7 [2] 12 e5 [2] 55 f4 [2] 1b f8 [2] 17 f2 [2] 00 f9 [2] 1b b7 [2] 26 }

  condition:
    any of them
}