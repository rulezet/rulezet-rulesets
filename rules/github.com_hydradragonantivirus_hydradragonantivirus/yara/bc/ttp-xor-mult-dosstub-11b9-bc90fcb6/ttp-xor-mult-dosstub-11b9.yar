rule TTP_XOR_MULT_DOSStub_11b9 {
  strings:
    $key_11b9 = { 45 d1 [2] 31 c9 [2] 76 cb [2] 31 da [2] 7f d6 [2] 73 dc [2] 64 d7 [2] 7f 99 [2] 42 }

  condition:
    any of them
}