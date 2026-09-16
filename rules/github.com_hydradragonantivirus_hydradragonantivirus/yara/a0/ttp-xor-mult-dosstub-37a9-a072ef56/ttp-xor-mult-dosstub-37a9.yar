rule TTP_XOR_MULT_DOSStub_37a9 {
  strings:
    $key_37a9 = { 63 c1 [2] 17 d9 [2] 50 db [2] 17 ca [2] 59 c6 [2] 55 cc [2] 42 c7 [2] 59 89 [2] 64 }

  condition:
    any of them
}