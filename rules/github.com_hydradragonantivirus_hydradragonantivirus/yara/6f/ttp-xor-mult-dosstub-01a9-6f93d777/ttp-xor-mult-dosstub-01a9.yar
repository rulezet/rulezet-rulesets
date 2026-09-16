rule TTP_XOR_MULT_DOSStub_01a9 {
  strings:
    $key_01a9 = { 55 c1 [2] 21 d9 [2] 66 db [2] 21 ca [2] 6f c6 [2] 63 cc [2] 74 c7 [2] 6f 89 [2] 52 }

  condition:
    any of them
}