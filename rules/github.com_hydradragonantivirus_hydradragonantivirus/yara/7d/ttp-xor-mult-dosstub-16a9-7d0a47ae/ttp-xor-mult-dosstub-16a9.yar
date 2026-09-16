rule TTP_XOR_MULT_DOSStub_16a9 {
  strings:
    $key_16a9 = { 42 c1 [2] 36 d9 [2] 71 db [2] 36 ca [2] 78 c6 [2] 74 cc [2] 63 c7 [2] 78 89 [2] 45 }

  condition:
    any of them
}