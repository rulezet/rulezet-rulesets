rule TTP_XOR_MULT_DOSStub_c0a5 {
  strings:
    $key_c0a5 = { 94 cd [2] e0 d5 [2] a7 d7 [2] e0 c6 [2] ae ca [2] a2 c0 [2] b5 cb [2] ae 85 [2] 93 }

  condition:
    any of them
}