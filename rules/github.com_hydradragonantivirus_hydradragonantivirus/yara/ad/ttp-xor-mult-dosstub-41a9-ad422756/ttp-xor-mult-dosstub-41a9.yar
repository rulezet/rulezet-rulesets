rule TTP_XOR_MULT_DOSStub_41a9 {
  strings:
    $key_41a9 = { 15 c1 [2] 61 d9 [2] 26 db [2] 61 ca [2] 2f c6 [2] 23 cc [2] 34 c7 [2] 2f 89 [2] 12 }

  condition:
    any of them
}