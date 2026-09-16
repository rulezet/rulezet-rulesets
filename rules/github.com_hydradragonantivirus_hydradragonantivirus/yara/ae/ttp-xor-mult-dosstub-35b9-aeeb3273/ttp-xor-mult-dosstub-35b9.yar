rule TTP_XOR_MULT_DOSStub_35b9 {
  strings:
    $key_35b9 = { 61 d1 [2] 15 c9 [2] 52 cb [2] 15 da [2] 5b d6 [2] 57 dc [2] 40 d7 [2] 5b 99 [2] 66 }

  condition:
    any of them
}