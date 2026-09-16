rule TTP_XOR_MULT_DOSStub_47a9 {
  strings:
    $key_47a9 = { 13 c1 [2] 67 d9 [2] 20 db [2] 67 ca [2] 29 c6 [2] 25 cc [2] 32 c7 [2] 29 89 [2] 14 }

  condition:
    any of them
}