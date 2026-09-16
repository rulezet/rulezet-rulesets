rule TTP_XOR_MULT_DOSStub_c5b2 {
  strings:
    $key_c5b2 = { 91 da [2] e5 c2 [2] a2 c0 [2] e5 d1 [2] ab dd [2] a7 d7 [2] b0 dc [2] ab 92 [2] 96 }

  condition:
    any of them
}