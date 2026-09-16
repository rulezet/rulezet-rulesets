rule TTP_XOR_MULT_DOSStub_e2a5 {
  strings:
    $key_e2a5 = { b6 cd [2] c2 d5 [2] 85 d7 [2] c2 c6 [2] 8c ca [2] 80 c0 [2] 97 cb [2] 8c 85 [2] b1 }

  condition:
    any of them
}