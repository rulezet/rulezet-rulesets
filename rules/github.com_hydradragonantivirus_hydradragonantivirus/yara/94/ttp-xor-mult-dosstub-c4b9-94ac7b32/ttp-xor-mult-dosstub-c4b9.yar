rule TTP_XOR_MULT_DOSStub_c4b9 {
  strings:
    $key_c4b9 = { 90 d1 [2] e4 c9 [2] a3 cb [2] e4 da [2] aa d6 [2] a6 dc [2] b1 d7 [2] aa 99 [2] 97 }

  condition:
    any of them
}