rule TTP_XOR_MULT_DOSStub_e1a5 {
  strings:
    $key_e1a5 = { b5 cd [2] c1 d5 [2] 86 d7 [2] c1 c6 [2] 8f ca [2] 83 c0 [2] 94 cb [2] 8f 85 [2] b2 }

  condition:
    any of them
}