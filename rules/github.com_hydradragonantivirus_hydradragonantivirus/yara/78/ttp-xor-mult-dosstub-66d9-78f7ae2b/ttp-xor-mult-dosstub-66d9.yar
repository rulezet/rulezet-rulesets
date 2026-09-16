rule TTP_XOR_MULT_DOSStub_66d9 {
  strings:
    $key_66d9 = { 32 b1 [2] 46 a9 [2] 01 ab [2] 46 ba [2] 08 b6 [2] 04 bc [2] 13 b7 [2] 08 f9 [2] 35 }

  condition:
    any of them
}