rule TTP_XOR_MULT_DOSStub_e1a9 {
  strings:
    $key_e1a9 = { b5 c1 [2] c1 d9 [2] 86 db [2] c1 ca [2] 8f c6 [2] 83 cc [2] 94 c7 [2] 8f 89 [2] b2 }

  condition:
    any of them
}