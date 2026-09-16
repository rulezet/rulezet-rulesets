rule TTP_XOR_MULT_DOSStub_11a9 {
  strings:
    $key_11a9 = { 45 c1 [2] 31 d9 [2] 76 db [2] 31 ca [2] 7f c6 [2] 73 cc [2] 64 c7 [2] 7f 89 [2] 42 }

  condition:
    any of them
}