rule TTP_XOR_MULT_DOSStub_23a9 {
  strings:
    $key_23a9 = { 77 c1 [2] 03 d9 [2] 44 db [2] 03 ca [2] 4d c6 [2] 41 cc [2] 56 c7 [2] 4d 89 [2] 70 }

  condition:
    any of them
}