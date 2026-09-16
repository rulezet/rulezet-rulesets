rule TTP_XOR_MULT_DOSStub_51a2 {
  strings:
    $key_51a2 = { 05 ca [2] 71 d2 [2] 36 d0 [2] 71 c1 [2] 3f cd [2] 33 c7 [2] 24 cc [2] 3f 82 [2] 02 }

  condition:
    any of them
}