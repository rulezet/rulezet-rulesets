rule TTP_XOR_MULT_DOSStub_c1a5 {
  strings:
    $key_c1a5 = { 95 cd [2] e1 d5 [2] a6 d7 [2] e1 c6 [2] af ca [2] a3 c0 [2] b4 cb [2] af 85 [2] 92 }

  condition:
    any of them
}