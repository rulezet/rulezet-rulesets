rule TTP_XOR_MULT_DOSStub_61a9 {
  strings:
    $key_61a9 = { 35 c1 [2] 41 d9 [2] 06 db [2] 41 ca [2] 0f c6 [2] 03 cc [2] 14 c7 [2] 0f 89 [2] 32 }

  condition:
    any of them
}