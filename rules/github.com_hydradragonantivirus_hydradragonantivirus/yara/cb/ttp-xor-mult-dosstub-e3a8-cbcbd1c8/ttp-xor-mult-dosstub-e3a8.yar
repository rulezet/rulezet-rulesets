rule TTP_XOR_MULT_DOSStub_e3a8 {
  strings:
    $key_e3a8 = { b7 c0 [2] c3 d8 [2] 84 da [2] c3 cb [2] 8d c7 [2] 81 cd [2] 96 c6 [2] 8d 88 [2] b0 }

  condition:
    any of them
}