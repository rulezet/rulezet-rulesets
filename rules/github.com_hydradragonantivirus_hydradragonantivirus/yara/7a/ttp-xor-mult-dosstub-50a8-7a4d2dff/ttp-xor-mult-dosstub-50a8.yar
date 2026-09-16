rule TTP_XOR_MULT_DOSStub_50a8 {
  strings:
    $key_50a8 = { 04 c0 [2] 70 d8 [2] 37 da [2] 70 cb [2] 3e c7 [2] 32 cd [2] 25 c6 [2] 3e 88 [2] 03 }

  condition:
    any of them
}