rule TTP_XOR_MULT_DOSStub_a7a9 {
  strings:
    $key_a7a9 = { f3 c1 [2] 87 d9 [2] c0 db [2] 87 ca [2] c9 c6 [2] c5 cc [2] d2 c7 [2] c9 89 [2] f4 }

  condition:
    any of them
}