rule TTP_XOR_MULT_DOSStub_c5a9 {
  strings:
    $key_c5a9 = { 91 c1 [2] e5 d9 [2] a2 db [2] e5 ca [2] ab c6 [2] a7 cc [2] b0 c7 [2] ab 89 [2] 96 }

  condition:
    any of them
}