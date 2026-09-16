rule TTP_XOR_MULT_DOSStub_c6a8 {
  strings:
    $key_c6a8 = { 92 c0 [2] e6 d8 [2] a1 da [2] e6 cb [2] a8 c7 [2] a4 cd [2] b3 c6 [2] a8 88 [2] 95 }

  condition:
    any of them
}