rule TTP_XOR_MULT_DOSStub_e3a2 {
  strings:
    $key_e3a2 = { b7 ca [2] c3 d2 [2] 84 d0 [2] c3 c1 [2] 8d cd [2] 81 c7 [2] 96 cc [2] 8d 82 [2] b0 }

  condition:
    any of them
}