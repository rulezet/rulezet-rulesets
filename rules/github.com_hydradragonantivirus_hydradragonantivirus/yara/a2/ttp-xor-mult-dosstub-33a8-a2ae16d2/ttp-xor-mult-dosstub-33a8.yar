rule TTP_XOR_MULT_DOSStub_33a8 {
  strings:
    $key_33a8 = { 67 c0 [2] 13 d8 [2] 54 da [2] 13 cb [2] 5d c7 [2] 51 cd [2] 46 c6 [2] 5d 88 [2] 60 }

  condition:
    any of them
}