rule TTP_XOR_MULT_DOSStub_21a9 {
  strings:
    $key_21a9 = { 75 c1 [2] 01 d9 [2] 46 db [2] 01 ca [2] 4f c6 [2] 43 cc [2] 54 c7 [2] 4f 89 [2] 72 }

  condition:
    any of them
}