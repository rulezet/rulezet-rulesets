rule TTP_XOR_MULT_DOSStub_05b4 {
  strings:
    $key_05b4 = { 51 dc [2] 25 c4 [2] 62 c6 [2] 25 d7 [2] 6b db [2] 67 d1 [2] 70 da [2] 6b 94 [2] 56 }

  condition:
    any of them
}