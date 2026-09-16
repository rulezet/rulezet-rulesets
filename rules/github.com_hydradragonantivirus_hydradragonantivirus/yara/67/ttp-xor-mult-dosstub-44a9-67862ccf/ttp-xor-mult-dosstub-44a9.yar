rule TTP_XOR_MULT_DOSStub_44a9 {
  strings:
    $key_44a9 = { 10 c1 [2] 64 d9 [2] 23 db [2] 64 ca [2] 2a c6 [2] 26 cc [2] 31 c7 [2] 2a 89 [2] 17 }

  condition:
    any of them
}