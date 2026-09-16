rule TTP_XOR_MULT_DOSStub_30b4 {
  strings:
    $key_30b4 = { 64 dc [2] 10 c4 [2] 57 c6 [2] 10 d7 [2] 5e db [2] 52 d1 [2] 45 da [2] 5e 94 [2] 63 }

  condition:
    any of them
}