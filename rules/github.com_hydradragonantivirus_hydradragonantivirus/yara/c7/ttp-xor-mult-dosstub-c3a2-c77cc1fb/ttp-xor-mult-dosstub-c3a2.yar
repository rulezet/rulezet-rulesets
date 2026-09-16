rule TTP_XOR_MULT_DOSStub_c3a2 {
  strings:
    $key_c3a2 = { 97 ca [2] e3 d2 [2] a4 d0 [2] e3 c1 [2] ad cd [2] a1 c7 [2] b6 cc [2] ad 82 [2] 90 }

  condition:
    any of them
}