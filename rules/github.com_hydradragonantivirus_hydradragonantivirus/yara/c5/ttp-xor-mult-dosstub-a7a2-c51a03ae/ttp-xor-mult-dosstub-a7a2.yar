rule TTP_XOR_MULT_DOSStub_a7a2 {
  strings:
    $key_a7a2 = { f3 ca [2] 87 d2 [2] c0 d0 [2] 87 c1 [2] c9 cd [2] c5 c7 [2] d2 cc [2] c9 82 [2] f4 }

  condition:
    any of them
}