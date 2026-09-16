rule TTP_XOR_MULT_DOSStub_17a8 {
  strings:
    $key_17a8 = { 43 c0 [2] 37 d8 [2] 70 da [2] 37 cb [2] 79 c7 [2] 75 cd [2] 62 c6 [2] 79 88 [2] 44 }

  condition:
    any of them
}