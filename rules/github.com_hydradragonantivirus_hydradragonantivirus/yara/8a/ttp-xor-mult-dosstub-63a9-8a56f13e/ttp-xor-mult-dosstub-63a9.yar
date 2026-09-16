rule TTP_XOR_MULT_DOSStub_63a9 {
  strings:
    $key_63a9 = { 37 c1 [2] 43 d9 [2] 04 db [2] 43 ca [2] 0d c6 [2] 01 cc [2] 16 c7 [2] 0d 89 [2] 30 }

  condition:
    any of them
}