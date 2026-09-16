rule TTP_XOR_MULT_DOSStub_06b4 {
  strings:
    $key_06b4 = { 52 dc [2] 26 c4 [2] 61 c6 [2] 26 d7 [2] 68 db [2] 64 d1 [2] 73 da [2] 68 94 [2] 55 }

  condition:
    any of them
}