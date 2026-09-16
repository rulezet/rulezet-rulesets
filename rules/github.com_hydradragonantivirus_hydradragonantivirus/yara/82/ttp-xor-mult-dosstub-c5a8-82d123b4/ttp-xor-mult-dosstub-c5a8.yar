rule TTP_XOR_MULT_DOSStub_c5a8 {
  strings:
    $key_c5a8 = { 91 c0 [2] e5 d8 [2] a2 da [2] e5 cb [2] ab c7 [2] a7 cd [2] b0 c6 [2] ab 88 [2] 96 }

  condition:
    any of them
}