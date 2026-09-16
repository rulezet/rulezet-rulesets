rule TTP_XOR_MULT_DOSStub_e4a2 {
  strings:
    $key_e4a2 = { b0 ca [2] c4 d2 [2] 83 d0 [2] c4 c1 [2] 8a cd [2] 86 c7 [2] 91 cc [2] 8a 82 [2] b7 }

  condition:
    any of them
}