rule TTP_XOR_MULT_DOSStub_65a9 {
  strings:
    $key_65a9 = { 31 c1 [2] 45 d9 [2] 02 db [2] 45 ca [2] 0b c6 [2] 07 cc [2] 10 c7 [2] 0b 89 [2] 36 }

  condition:
    any of them
}