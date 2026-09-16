rule TTP_XOR_MULT_DOSStub_c3a5 {
  strings:
    $key_c3a5 = { 97 cd [2] e3 d5 [2] a4 d7 [2] e3 c6 [2] ad ca [2] a1 c0 [2] b6 cb [2] ad 85 [2] 90 }

  condition:
    any of them
}