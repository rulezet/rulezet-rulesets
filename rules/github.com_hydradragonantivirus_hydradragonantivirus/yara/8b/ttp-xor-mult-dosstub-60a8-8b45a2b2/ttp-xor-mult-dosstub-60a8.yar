rule TTP_XOR_MULT_DOSStub_60a8 {
  strings:
    $key_60a8 = { 34 c0 [2] 40 d8 [2] 07 da [2] 40 cb [2] 0e c7 [2] 02 cd [2] 15 c6 [2] 0e 88 [2] 33 }

  condition:
    any of them
}