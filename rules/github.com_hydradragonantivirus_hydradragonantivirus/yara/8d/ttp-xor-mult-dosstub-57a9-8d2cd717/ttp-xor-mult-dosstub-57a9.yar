rule TTP_XOR_MULT_DOSStub_57a9 {
  strings:
    $key_57a9 = { 03 c1 [2] 77 d9 [2] 30 db [2] 77 ca [2] 39 c6 [2] 35 cc [2] 22 c7 [2] 39 89 [2] 04 }

  condition:
    any of them
}