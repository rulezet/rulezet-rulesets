rule TTP_XOR_MULT_DOSStub_22a9 {
  strings:
    $key_22a9 = { 76 c1 [2] 02 d9 [2] 45 db [2] 02 ca [2] 4c c6 [2] 40 cc [2] 57 c7 [2] 4c 89 [2] 71 }

  condition:
    any of them
}