rule TTP_XOR_MULT_DOSStub_10a9 {
  strings:
    $key_10a9 = { 44 c1 [2] 30 d9 [2] 77 db [2] 30 ca [2] 7e c6 [2] 72 cc [2] 65 c7 [2] 7e 89 [2] 43 }

  condition:
    any of them
}