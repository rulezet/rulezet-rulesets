rule TTP_XOR_MULT_DOSStub_c4a8 {
  strings:
    $key_c4a8 = { 90 c0 [2] e4 d8 [2] a3 da [2] e4 cb [2] aa c7 [2] a6 cd [2] b1 c6 [2] aa 88 [2] 97 }

  condition:
    any of them
}