rule TTP_XOR_MULT_DOSStub_54a2 {
  strings:
    $key_54a2 = { 00 ca [2] 74 d2 [2] 33 d0 [2] 74 c1 [2] 3a cd [2] 36 c7 [2] 21 cc [2] 3a 82 [2] 07 }

  condition:
    any of them
}