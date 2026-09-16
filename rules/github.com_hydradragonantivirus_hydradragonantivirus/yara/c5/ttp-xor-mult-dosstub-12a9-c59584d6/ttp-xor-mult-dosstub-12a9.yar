rule TTP_XOR_MULT_DOSStub_12a9 {
  strings:
    $key_12a9 = { 46 c1 [2] 32 d9 [2] 75 db [2] 32 ca [2] 7c c6 [2] 70 cc [2] 67 c7 [2] 7c 89 [2] 41 }

  condition:
    any of them
}