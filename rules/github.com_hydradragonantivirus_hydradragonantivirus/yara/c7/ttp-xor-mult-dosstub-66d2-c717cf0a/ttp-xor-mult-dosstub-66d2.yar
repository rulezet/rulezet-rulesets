rule TTP_XOR_MULT_DOSStub_66d2 {
  strings:
    $key_66d2 = { 32 ba [2] 46 a2 [2] 01 a0 [2] 46 b1 [2] 08 bd [2] 04 b7 [2] 13 bc [2] 08 f2 [2] 35 }

  condition:
    any of them
}