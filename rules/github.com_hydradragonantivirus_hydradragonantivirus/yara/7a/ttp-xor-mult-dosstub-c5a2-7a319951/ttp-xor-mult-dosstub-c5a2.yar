rule TTP_XOR_MULT_DOSStub_c5a2 {
  strings:
    $key_c5a2 = { 91 ca [2] e5 d2 [2] a2 d0 [2] e5 c1 [2] ab cd [2] a7 c7 [2] b0 cc [2] ab 82 [2] 96 }

  condition:
    any of them
}