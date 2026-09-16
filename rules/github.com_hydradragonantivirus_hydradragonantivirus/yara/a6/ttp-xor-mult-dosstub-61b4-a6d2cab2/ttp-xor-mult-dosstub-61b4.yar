rule TTP_XOR_MULT_DOSStub_61b4 {
  strings:
    $key_61b4 = { 35 dc [2] 41 c4 [2] 06 c6 [2] 41 d7 [2] 0f db [2] 03 d1 [2] 14 da [2] 0f 94 [2] 32 }

  condition:
    any of them
}