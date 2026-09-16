rule TTP_XOR_MULT_DOSStub_14a8 {
  strings:
    $key_14a8 = { 40 c0 [2] 34 d8 [2] 73 da [2] 34 cb [2] 7a c7 [2] 76 cd [2] 61 c6 [2] 7a 88 [2] 47 }

  condition:
    any of them
}