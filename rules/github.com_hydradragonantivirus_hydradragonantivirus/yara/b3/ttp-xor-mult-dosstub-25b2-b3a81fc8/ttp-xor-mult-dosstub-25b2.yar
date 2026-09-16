rule TTP_XOR_MULT_DOSStub_25b2 {
  strings:
    $key_25b2 = { 71 da [2] 05 c2 [2] 42 c0 [2] 05 d1 [2] 4b dd [2] 47 d7 [2] 50 dc [2] 4b 92 [2] 76 }

  condition:
    any of them
}