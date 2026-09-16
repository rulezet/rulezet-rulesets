rule TTP_XOR_MULT_DOSStub_c5a5 {
  strings:
    $key_c5a5 = { 91 cd [2] e5 d5 [2] a2 d7 [2] e5 c6 [2] ab ca [2] a7 c0 [2] b0 cb [2] ab 85 [2] 96 }

  condition:
    any of them
}