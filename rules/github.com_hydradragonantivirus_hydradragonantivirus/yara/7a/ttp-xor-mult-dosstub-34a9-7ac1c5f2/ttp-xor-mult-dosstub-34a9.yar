rule TTP_XOR_MULT_DOSStub_34a9 {
  strings:
    $key_34a9 = { 60 c1 [2] 14 d9 [2] 53 db [2] 14 ca [2] 5a c6 [2] 56 cc [2] 41 c7 [2] 5a 89 [2] 67 }

  condition:
    any of them
}