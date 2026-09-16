rule TTP_XOR_MULT_DOSStub_c1a2 {
  strings:
    $key_c1a2 = { 95 ca [2] e1 d2 [2] a6 d0 [2] e1 c1 [2] af cd [2] a3 c7 [2] b4 cc [2] af 82 [2] 92 }

  condition:
    any of them
}