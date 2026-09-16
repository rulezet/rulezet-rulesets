rule TTP_XOR_MULT_DOSStub_5597 {
  strings:
    $key_5597 = { 01 ff [2] 75 e7 [2] 32 e5 [2] 75 f4 [2] 3b f8 [2] 37 f2 [2] 20 f9 [2] 3b b7 [2] 06 }

  condition:
    any of them
}