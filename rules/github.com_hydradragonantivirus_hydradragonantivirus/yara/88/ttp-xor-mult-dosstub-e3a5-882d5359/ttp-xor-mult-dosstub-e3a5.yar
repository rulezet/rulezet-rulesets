rule TTP_XOR_MULT_DOSStub_e3a5 {
  strings:
    $key_e3a5 = { b7 cd [2] c3 d5 [2] 84 d7 [2] c3 c6 [2] 8d ca [2] 81 c0 [2] 96 cb [2] 8d 85 [2] b0 }

  condition:
    any of them
}