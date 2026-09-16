rule TTP_XOR_MULT_DOSStub_71a9 {
  strings:
    $key_71a9 = { 25 c1 [2] 51 d9 [2] 16 db [2] 51 ca [2] 1f c6 [2] 13 cc [2] 04 c7 [2] 1f 89 [2] 22 }

  condition:
    any of them
}