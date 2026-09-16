rule TTP_XOR_MULT_DOSStub_52a9 {
  strings:
    $key_52a9 = { 06 c1 [2] 72 d9 [2] 35 db [2] 72 ca [2] 3c c6 [2] 30 cc [2] 27 c7 [2] 3c 89 [2] 01 }

  condition:
    any of them
}