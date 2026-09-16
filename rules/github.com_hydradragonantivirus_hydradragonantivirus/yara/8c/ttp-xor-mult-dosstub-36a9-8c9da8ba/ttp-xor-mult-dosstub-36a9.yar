rule TTP_XOR_MULT_DOSStub_36a9 {
  strings:
    $key_36a9 = { 62 c1 [2] 16 d9 [2] 51 db [2] 16 ca [2] 58 c6 [2] 54 cc [2] 43 c7 [2] 58 89 [2] 65 }

  condition:
    any of them
}