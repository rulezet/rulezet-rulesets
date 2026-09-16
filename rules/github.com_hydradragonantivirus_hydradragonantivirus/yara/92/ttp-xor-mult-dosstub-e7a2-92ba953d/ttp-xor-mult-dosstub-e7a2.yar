rule TTP_XOR_MULT_DOSStub_e7a2 {
  strings:
    $key_e7a2 = { b3 ca [2] c7 d2 [2] 80 d0 [2] c7 c1 [2] 89 cd [2] 85 c7 [2] 92 cc [2] 89 82 [2] b4 }

  condition:
    any of them
}