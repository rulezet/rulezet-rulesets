rule TTP_XOR_MULT_DOSStub_66b4 {
  strings:
    $key_66b4 = { 32 dc [2] 46 c4 [2] 01 c6 [2] 46 d7 [2] 08 db [2] 04 d1 [2] 13 da [2] 08 94 [2] 35 }

  condition:
    any of them
}