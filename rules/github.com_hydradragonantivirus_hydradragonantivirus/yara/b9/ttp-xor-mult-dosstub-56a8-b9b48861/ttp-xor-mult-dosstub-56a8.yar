rule TTP_XOR_MULT_DOSStub_56a8 {
  strings:
    $key_56a8 = { 02 c0 [2] 76 d8 [2] 31 da [2] 76 cb [2] 38 c7 [2] 34 cd [2] 23 c6 [2] 38 88 [2] 05 }

  condition:
    any of them
}