rule TTP_XOR_MULT_DOSStub_00a9 {
  strings:
    $key_00a9 = { 54 c1 [2] 20 d9 [2] 67 db [2] 20 ca [2] 6e c6 [2] 62 cc [2] 75 c7 [2] 6e 89 [2] 53 }

  condition:
    any of them
}