rule TTP_XOR_MULT_DOSStub_e6a9 {
  strings:
    $key_e6a9 = { b2 c1 [2] c6 d9 [2] 81 db [2] c6 ca [2] 88 c6 [2] 84 cc [2] 93 c7 [2] 88 89 [2] b5 }

  condition:
    any of them
}