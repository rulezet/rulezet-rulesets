rule TTP_XOR_MULT_DOSStub_61b2 {
  strings:
    $key_61b2 = { 35 da [2] 41 c2 [2] 06 c0 [2] 41 d1 [2] 0f dd [2] 03 d7 [2] 14 dc [2] 0f 92 [2] 32 }

  condition:
    any of them
}