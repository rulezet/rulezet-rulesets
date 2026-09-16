rule TTP_XOR_MULT_DOSStub_e5a9 {
  strings:
    $key_e5a9 = { b1 c1 [2] c5 d9 [2] 82 db [2] c5 ca [2] 8b c6 [2] 87 cc [2] 90 c7 [2] 8b 89 [2] b6 }

  condition:
    any of them
}