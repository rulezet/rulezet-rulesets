rule TTP_XOR_MULT_DOSStub_f1a2 {
  strings:
    $key_f1a2 = { a5 ca [2] d1 d2 [2] 96 d0 [2] d1 c1 [2] 9f cd [2] 93 c7 [2] 84 cc [2] 9f 82 [2] a2 }

  condition:
    any of them
}