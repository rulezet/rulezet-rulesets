rule TTP_XOR_MULT_DOSStub_e1a2 {
  strings:
    $key_e1a2 = { b5 ca [2] c1 d2 [2] 86 d0 [2] c1 c1 [2] 8f cd [2] 83 c7 [2] 94 cc [2] 8f 82 [2] b2 }

  condition:
    any of them
}