rule TTP_XOR_MULT_DOSStub_70a8 {
  strings:
    $key_70a8 = { 24 c0 [2] 50 d8 [2] 17 da [2] 50 cb [2] 1e c7 [2] 12 cd [2] 05 c6 [2] 1e 88 [2] 23 }

  condition:
    any of them
}