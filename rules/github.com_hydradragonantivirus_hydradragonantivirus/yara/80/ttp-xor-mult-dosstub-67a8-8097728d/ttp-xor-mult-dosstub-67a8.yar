rule TTP_XOR_MULT_DOSStub_67a8 {
  strings:
    $key_67a8 = { 33 c0 [2] 47 d8 [2] 00 da [2] 47 cb [2] 09 c7 [2] 05 cd [2] 12 c6 [2] 09 88 [2] 34 }

  condition:
    any of them
}