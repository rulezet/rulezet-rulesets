rule TTP_XOR_MULT_DOSStub_67a9 {
  strings:
    $key_67a9 = { 33 c1 [2] 47 d9 [2] 00 db [2] 47 ca [2] 09 c6 [2] 05 cc [2] 12 c7 [2] 09 89 [2] 34 }

  condition:
    any of them
}