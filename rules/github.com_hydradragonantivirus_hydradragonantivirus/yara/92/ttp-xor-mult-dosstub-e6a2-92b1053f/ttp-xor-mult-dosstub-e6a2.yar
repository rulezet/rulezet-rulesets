rule TTP_XOR_MULT_DOSStub_e6a2 {
  strings:
    $key_e6a2 = { b2 ca [2] c6 d2 [2] 81 d0 [2] c6 c1 [2] 88 cd [2] 84 c7 [2] 93 cc [2] 88 82 [2] b5 }

  condition:
    any of them
}