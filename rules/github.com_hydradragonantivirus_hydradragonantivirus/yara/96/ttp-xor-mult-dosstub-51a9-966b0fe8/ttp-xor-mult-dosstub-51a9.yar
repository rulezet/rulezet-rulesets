rule TTP_XOR_MULT_DOSStub_51a9 {
  strings:
    $key_51a9 = { 05 c1 [2] 71 d9 [2] 36 db [2] 71 ca [2] 3f c6 [2] 33 cc [2] 24 c7 [2] 3f 89 [2] 02 }

  condition:
    any of them
}