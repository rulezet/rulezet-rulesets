rule TTP_XOR_MULT_DOSStub_25a8 {
  strings:
    $key_25a8 = { 71 c0 [2] 05 d8 [2] 42 da [2] 05 cb [2] 4b c7 [2] 47 cd [2] 50 c6 [2] 4b 88 [2] 76 }

  condition:
    any of them
}