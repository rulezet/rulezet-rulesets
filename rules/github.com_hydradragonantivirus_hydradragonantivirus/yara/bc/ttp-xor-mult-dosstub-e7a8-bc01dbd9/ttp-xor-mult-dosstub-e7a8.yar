rule TTP_XOR_MULT_DOSStub_e7a8 {
  strings:
    $key_e7a8 = { b3 c0 [2] c7 d8 [2] 80 da [2] c7 cb [2] 89 c7 [2] 85 cd [2] 92 c6 [2] 89 88 [2] b4 }

  condition:
    any of them
}